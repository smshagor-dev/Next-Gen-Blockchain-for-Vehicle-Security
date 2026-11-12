"""Disk-backed audit for duplicate CAM receptions and potential split leakage.

A sender+pseudonym+messageID+sendTime fingerprint is a conservative heuristic,
not cryptographic proof of a unique radio transmission or physical identity.
This tool reports ingestion-quality counts only; it never estimates detection
performance or treats CAM attacker labels as incident ground truth.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Sequence

REQUIRED = (
    "archive_sha256", "source_split", "receiver_log", "sender_id",
    "sender_alias", "message_id", "send_time_raw", "attacker_label"
)
VALID_SPLITS = {"train", "validation", "test", "unverified"}
VALID_LABELS = {"", "0", "1"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for buf in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(buf)
    return digest.hexdigest()


def audit(input_csv: Path, source_manifest: Path, output_json: Path) -> dict[str, Any]:
    """Audit normalized receiver-level CAM records without loading all in RAM."""
    input_csv, source_manifest, output_json = map(Path, (input_csv, source_manifest, output_json))
    source = json.loads(source_manifest.read_text(encoding="utf-8"))
    if not isinstance(source, dict):
        raise ValueError("source manifest is not an object")
    csv_digest = sha256_file(input_csv)
    if source.get("normalized_csv_sha256") != csv_digest:
        raise ValueError("normalized CAM CSV SHA-256 mismatch")
    source_sha = source.get("source_sha256_verified")
    if not isinstance(source_sha, str) or len(source_sha) != 64:
        raise ValueError("source manifest has no verified parent archive digest")

    counts: Counter[str] = Counter()
    per_split: dict[str, Counter[str]] = defaultdict(Counter)
    with tempfile.TemporaryDirectory(prefix="veremi-cam-audit-") as temporary:
        db = sqlite3.connect(str(Path(temporary) / "audit.sqlite3"))
        try:
            db.execute("""CREATE TABLE messages (
                sender_id TEXT NOT NULL,
                sender_alias TEXT NOT NULL,
                message_id TEXT NOT NULL,
                send_time TEXT NOT NULL,
                source_split TEXT NOT NULL,
                receiver_log TEXT NOT NULL,
                attacker_label TEXT NOT NULL,
                split_overlap_noted INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (sender_id, sender_alias, message_id, send_time)
            ) WITHOUT ROWID""")
            with input_csv.open("r", newline="", encoding="utf-8-sig") as source_stream:
                rows = csv.DictReader(source_stream)
                missing = set(REQUIRED) - set(rows.fieldnames or ())
                if missing:
                    raise ValueError("missing required CAM fields: " + ", ".join(sorted(missing)))
                for line, row in enumerate(rows, 2):
                    if None in row or any(row.get(c) is None for c in REQUIRED):
                        raise ValueError(f"invalid CSV row {line}")
                    split, label = row["source_split"], row["attacker_label"]
                    if split not in VALID_SPLITS or label not in VALID_LABELS:
                        raise ValueError(f"invalid source split/label at CSV line {line}")
                    if row["archive_sha256"] != source_sha:
                        raise ValueError(f"source archive identity changed at CSV line {line}")
                    key = tuple(row[c] for c in ("sender_id", "sender_alias", "message_id", "send_time_raw"))
                    if any(not v.strip() for v in key) or not row["receiver_log"].strip():
                        raise ValueError(f"missing transmission fingerprint at CSV line {line}")
                    counts["cam_receptions"] += 1
                    per_split[split]["cam_receptions"] += 1
                    per_split[split]["label_1" if label == "1" else
                                     "label_0" if label == "0" else "unlabeled"] += 1
                    prior = db.execute(
                        """SELECT source_split, receiver_log, attacker_label, split_overlap_noted
                        FROM messages WHERE sender_id=? AND sender_alias=? AND message_id=? AND send_time=?""",
                        key,
                    ).fetchone()
                    if prior is None:
                        db.execute(
                            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,0)",
                            (*key, split, row["receiver_log"], label),
                        )
                        counts["unique_message_fingerprints"] += 1
                    else:
                        prior_split, prior_receiver, prior_label, overlap_noted = prior
                        counts["repeated_receptions"] += 1
                        if prior_receiver == row["receiver_log"]:
                            counts["same_receiver_fingerprint_repeat"] += 1
                        else:
                            counts["cross_receiver_fingerprint_repeat"] += 1
                        if prior_split != split:
                            counts["cross_split_receptions"] += 1
                            if not overlap_noted:
                                counts["cross_split_unique_fingerprints"] += 1
                                db.execute(
                                    """UPDATE messages SET split_overlap_noted=1
                                    WHERE sender_id=? AND sender_alias=? AND message_id=? AND send_time=?""",
                                    key,
                                )
                        if label and prior_label and prior_label != label:
                            counts["conflicting_labels_on_same_fingerprint"] += 1
                        if not prior_label and label:
                            db.execute(
                                """UPDATE messages SET attacker_label=?
                                WHERE sender_id=? AND sender_alias=? AND message_id=? AND send_time=?""",
                                (label, *key),
                            )
            db.commit()
        finally:
            db.close()
    if counts["cam_receptions"] == 0:
        raise ValueError("empty normalized CAM CSV")
    if counts["cam_receptions"] != source.get("received_cam_rows"):
        raise ValueError("source manifest received_cam_rows differs from CSV")

    report = {
        "status": "cam_reception_fingerprint_audit_only",
        "publication_ready": False,
        "normalized_csv_sha256_verified": csv_digest,
        "parent_source_archive_sha256": source_sha,
        "source_manifest_sha256": sha256_file(source_manifest),
        "fingerprint_fields": ["sender_id", "sender_alias", "message_id", "send_time_raw"],
        "counts": dict(counts),
        "per_source_split": {name: dict(c) for name, c in sorted(per_split.items())},
        "limitations": [
            "A matching tuple is a heuristic retransmission/receiver-duplicate candidate, not proof of the same physical radio packet.",
            "Source train/test split labels are preserved and potential overlap is reported, not adjudicated as confirmed leakage.",
            "A single transmitted CAM may appear at multiple receivers and cannot be counted as independent trial replicates.",
            "No true incident labels, authenticated vehicle enrollment, detector inference or scientific efficacy are established.",
            "The original archive's distribution/reuse license remains subject to independent verification.",
        ],
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit real per-receiver CAM duplicates without treating them as independent trials.")
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--source-manifest", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args(argv)
    report = audit(Path(args.input_csv), Path(args.source_manifest), Path(args.output_json))
    print(json.dumps({"status": report["status"], "counts": report["counts"],
                      "publication_ready": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
