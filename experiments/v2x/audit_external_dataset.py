"""Fail-closed external V2X/CAN dataset provenance and leakage audit.

This tool audits source bytes, split isolation and metadata assertions.
It does NOT certify that a named dataset is authentic, labels are correct,
CAN messages are safe, or a source license permits redistribution.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re

MAX_BYTES = 64 * 1024 * 1024
FIELDS = {
    "schema_version", "dataset_name", "dataset_family", "source_url",
    "source_release", "license_id", "license_url", "retrieved_utc",
    "original_archive_sha256", "original_archive_bytes",
    "extractor_commit", "annotation_protocol", "split_protocol",
    "split_index_sha256", "split_index_bytes",
}
SPLIT_COLUMNS = ("source_record_id", "source_group_id", "split", "label")
HEX = re.compile(r"^[a-f0-9]{64}$")
ALLOWED_FAMILIES = {"veremi_nextgen", "can_intrusion", "other_v2x"}
ALLOWED_SPLITS = {"train", "validation", "test"}


def strict_json(data: bytes) -> dict:
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate provenance JSON key")
            obj[key] = value
        return obj
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid provenance JSON") from exc


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def audit(manifest_bytes: bytes, original_archive: bytes,
          split_index: bytes, *, pinned_manifest_sha256: str) -> dict:
    if any(not isinstance(x, bytes) or len(x) > MAX_BYTES for x in
           (manifest_bytes, original_archive, split_index)):
        raise ValueError("input exceeds bounded size or is not bytes")
    if not isinstance(pinned_manifest_sha256, str) or not HEX.fullmatch(pinned_manifest_sha256):
        raise ValueError("invalid external manifest pin")
    if sha(manifest_bytes) != pinned_manifest_sha256:
        raise ValueError("externally pinned manifest mismatch")
    m = strict_json(manifest_bytes)
    if not isinstance(m, dict) or set(m) != FIELDS or type(m["schema_version"]) is not int or m["schema_version"] != 1:
        raise ValueError("provenance schema mismatch")
    if m["dataset_family"] not in ALLOWED_FAMILIES:
        raise ValueError("unsupported dataset family")
    for key in FIELDS - {"schema_version", "original_archive_bytes", "split_index_bytes"}:
        if not isinstance(m[key], str) or not m[key].strip():
            raise ValueError("missing provenance field: " + key)
    for key in ("original_archive_sha256", "split_index_sha256", "extractor_commit"):
        if not HEX.fullmatch(m[key]):
            raise ValueError("invalid provenance digest: " + key)
    for key, data in (("original_archive", original_archive), ("split_index", split_index)):
        if type(m[key + "_bytes"]) is not int or m[key + "_bytes"] != len(data):
            raise ValueError(key + " byte count mismatch")
        if sha(data) != m[key + "_sha256"]:
            raise ValueError(key + " SHA-256 mismatch")
    if not m["source_url"].startswith("https://") or not m["license_url"].startswith("https://"):
        raise ValueError("dataset source and license must be HTTPS URLs")
    from datetime import datetime, timezone
    try:
        t = datetime.fromisoformat(m["retrieved_utc"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid retrieval timestamp") from exc
    if t.utcoffset() is None or t.utcoffset().total_seconds() != 0:
        raise ValueError("retrieval timestamp must be UTC")
    try:
        decoded = split_index.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("invalid split index encoding") from exc
    reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
    if reader.fieldnames != list(SPLIT_COLUMNS):
        raise ValueError("split index schema mismatch")
    seen_records = set()
    group_split = {}
    counts = {name: 0 for name in ALLOWED_SPLITS}
    label_counts = {name: {} for name in ALLOWED_SPLITS}
    for row in reader:
        if None in row or any(not isinstance(row[k], str) or not row[k].strip()
                              for k in SPLIT_COLUMNS):
            raise ValueError("malformed split index row")
        record, group, split, label = (row[k] for k in SPLIT_COLUMNS)
        if split not in ALLOWED_SPLITS:
            raise ValueError("invalid split")
        if record in seen_records:
            raise ValueError("duplicate source record across splits")
        seen_records.add(record)
        if group in group_split and group_split[group] != split:
            raise ValueError("source group leakage across splits")
        group_split[group] = split
        counts[split] += 1
        label_counts[split][label] = label_counts[split].get(label, 0) + 1
        if len(seen_records) > 500000:
            raise ValueError("split index exceeds bounded record count")
    if not seen_records or not counts["train"] or not counts["test"]:
        raise ValueError("nonempty train and test splits required")
    return {
        "schema_version": 1, "publication_ready": False,
        "status": "source_hash_and_split_integrity_checked_only",
        "dataset_name_claim": m["dataset_name"],
        "dataset_family_claim": m["dataset_family"],
        "manifest_sha256": sha(manifest_bytes),
        "archive_sha256": sha(original_archive),
        "split_index_sha256": sha(split_index),
        "split_counts": counts,
        "split_label_counts": label_counts,
        "unique_source_groups": len(group_split),
        "limitations": [
            "Source URL, release, license and extractor commit are operator assertions, not independently verified against publisher.",
            "Original archive is treated as opaque bytes; file-format parsing, extraction safety and labels are not authenticated.",
            "Group-disjoint split index prevents declared group overlap, but does not detect duplicate underlying recordings with different IDs.",
            "No VeReMi NextGen or CAN source data was downloaded or experimentally evaluated by this audit.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Audit pinned source bytes and leakage-safe split declarations")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--original-archive", type=Path, required=True)
    p.add_argument("--split-index", type=Path, required=True)
    p.add_argument("--pinned-manifest-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = audit(a.manifest.read_bytes(), a.original_archive.read_bytes(),
                   a.split_index.read_bytes(),
                   pinned_manifest_sha256=a.pinned_manifest_sha256)
    if a.output.exists():
        raise FileExistsError("refuse to overwrite existing audit evidence")
    payload = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
    a.output.write_text(payload, encoding="utf-8")
    print(json.dumps({"report_sha256": sha(payload.encode()), "publication_ready": False}))


if __name__ == "__main__":
    main()
