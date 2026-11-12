"""VeReMi NextGen archive reader: verified bytes, CAM-level labels, no event fabrication.

Uses documented per-receiver JSON arrays. Never converts a CAM \`attacker\`
label into remote incident ground truth, geodetic coordinates, or evidence of
authenticated independent sensor observations. Source distribution licensing
must be reviewed separately from the dataset generator's source-code license.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

OFFICIAL_DATASET = "https://zenodo.org/records/19665762"
OFFICIAL_DOCS = "https://github.com/VeReMi-dataset/VeReMi-NextGen/blob/main/Documentation/README.md"
SOURCE_FIELDS = (
    "archive_sha256", "receiver_log", "message_index", "sender_id",
    "sender_alias", "message_id", "attack_subset_declared", "attacker_label",
    "send_time_raw", "receive_time_raw", "receiver_pos_x", "receiver_pos_y",
    "receiver_pos_z", "sender_pos_x", "sender_pos_y", "sender_pos_z",
    "receiver_speed", "sender_speed", "sender_acceleration", "sender_heading",
)
HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _finite(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(label + " must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(label + " must be finite")
    return result


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(label + " must be a nonnegative integer")
    return value


def _coords(value: object, label: str) -> list[str]:
    if value is None:
        return ["", "", ""]
    if not isinstance(value, list) or len(value) != 3:
        raise ValueError(label + " must contain three planar coordinates")
    return [str(_finite(x, label)) for x in value]


def normalize_cam(message: object, *, receiver_log: str, index: int, sha: str, subset: str) -> dict:
    if not isinstance(message, dict):
        raise ValueError("CAM record must be an object")
    sender = message.get("sender")
    receiver = message.get("receiver")
    if not isinstance(sender, dict) or not isinstance(receiver, dict):
        raise ValueError("CAM requires sender and receiver telemetry objects")
    if not isinstance(message.get("sender_id"), str) or not message["sender_id"].strip():
        raise ValueError("CAM sender_id must be non-empty")
    attacker = message.get("attacker")
    if isinstance(attacker, bool) or not isinstance(attacker, int) or attacker not in (0, 1):
        raise ValueError("CAM attacker label must be integer 0 or 1")
    alias = _nonnegative_integer(message.get("sender_alias"), "sender_alias")
    msgid = _nonnegative_integer(message.get("messageID"), "messageID")
    sent = _finite(message.get("sendTime"), "sendTime")
    received = _finite(message.get("rcvTime"), "rcvTime")
    sender_pos = _coords(sender.get("pos"), "sender.pos")
    receiver_pos = _coords(receiver.get("pos"), "receiver.pos")
    return {
        "archive_sha256": sha,
        "receiver_log": receiver_log,
        "message_index": index,
        "sender_id": message["sender_id"],
        "sender_alias": alias,
        "message_id": msgid,
        "attack_subset_declared": subset,
        "attacker_label": attacker,
        "send_time_raw": repr(sent),
        "receive_time_raw": repr(received),
        "receiver_pos_x": receiver_pos[0],
        "receiver_pos_y": receiver_pos[1],
        "receiver_pos_z": receiver_pos[2],
        "sender_pos_x": sender_pos[0],
        "sender_pos_y": sender_pos[1],
        "sender_pos_z": sender_pos[2],
        "receiver_speed": _optional_numeric(receiver.get("spd"), "receiver.spd"),
        "sender_speed": _optional_numeric(sender.get("spd"), "sender.spd"),
        "sender_acceleration": _optional_numeric(sender.get("acl"), "sender.acl"),
        "sender_heading": _optional_numeric(sender.get("hed"), "sender.hed"),
    }


def _optional_numeric(value: object, label: str) -> str:
    return "" if value is None else repr(_finite(value, label))


def _valid_zip_path(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return bool(name) and not path.is_absolute() and not any(p == ".." for p in path.parts)


def import_archive(
    archive: Path, output_dir: Path, *,
    expected_sha256: str, split: str, attack_subset: str,
    release_tag: str, max_json_files: int = 20000,
    max_entry_bytes: int = 256 * 1024 * 1024,
    max_total_bytes: int = 4 * 1024 * 1024 * 1024,
) -> dict[str, Any]:
    """Normalize original CAM fields with strict source-byte/hash provenance.

    Memory is bounded per JSON receiver file (not whole 36+GB dataset). Archive
    entries are read without extraction. Callers can adjust resource caps
    explicitly if legitimate receiver files exceed the defaults.
    """
    archive = Path(archive)
    if not HEX64.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a 64-character hex digest")
    if split not in ("train", "validation", "test"):
        raise ValueError("split must be train, validation or test")
    if not attack_subset or not release_tag or any(c in attack_subset for c in "/\\"):
        raise ValueError("attack_subset and release_tag must be explicit metadata")
    if min(max_json_files, max_entry_bytes, max_total_bytes) < 1:
        raise ValueError("archive resource caps must be positive")
    actual_sha = sha256_file(archive)
    if actual_sha.lower() != expected_sha256.lower():
        raise ValueError("VeReMi archive SHA-256 does not match expected release digest")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    csv_path = out / "veremi_cam_messages.csv"
    summary_path = out / "veremi_cam_manifest.json"
    message_count, positive_count, files_seen, bytes_read = 0, 0, 0, 0
    with zipfile.ZipFile(archive) as z, csv_path.open("w", encoding="utf-8", newline="") as dest:
        writer = csv.DictWriter(dest, fieldnames=SOURCE_FIELDS)
        writer.writeheader()
        for entry in z.infolist():
            if not _valid_zip_path(entry.filename):
                raise ValueError("unsafe ZIP entry path")
            if entry.is_dir():
                continue
            if not entry.filename.lower().endswith(".json"):
                continue
            files_seen += 1
            if files_seen > max_json_files:
                raise ValueError("JSON receiver file count exceeded limit")
            if entry.file_size > max_entry_bytes or bytes_read + entry.file_size > max_total_bytes:
                raise ValueError("archive decompressed size exceeds configured resource cap")
            bytes_read += entry.file_size
            try:
                with z.open(entry, "r") as input_stream:
                    # Per-entry bound comes from verified ZIP metadata. In
                    # addition, limit the actual bytes read for malformed sizes.
                    raw = input_stream.read(max_entry_bytes + 1)
                    if len(raw) > max_entry_bytes or len(raw) != entry.file_size:
                        raise ValueError("receiver JSON size mismatch or exceeds cap")
                    messages = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid receiver JSON: {entry.filename}") from exc
            if not isinstance(messages, list):
                raise ValueError(f"receiver JSON must be an array: {entry.filename}")
            for index, message in enumerate(messages):
                normalized = normalize_cam(message, receiver_log=entry.filename, index=index,
                                           sha=actual_sha, subset=attack_subset)
                writer.writerow(normalized)
                message_count += 1
                positive_count += normalized["attacker_label"]
    if files_seen == 0:
        raise ValueError("archive contained no receiver JSON files")

    manifest = {
        "status": "normalized_cam_message_level_only",
        "publication_ready": False,
        "source_dataset": "VeReMi NextGen (2026)",
        "source_release_tag_declared": release_tag,
        "source_reference": OFFICIAL_DATASET,
        "format_reference": OFFICIAL_DOCS,
        "source_archive": archive.name,
        "source_sha256_verified": actual_sha,
        "split_declared": split,
        "attack_subset_declared": attack_subset,
        "dataset_distribution_license": "NOT_VERIFIED_CHECK_SOURCE_RECORD",
        "receiver_json_files": files_seen,
        "received_cam_rows": message_count,
        "cam_attacker_label_one_rows": positive_count,
        "cam_attacker_label_zero_rows": message_count - positive_count,
        "normalized_csv_sha256": sha256_file(csv_path),
        "time_units": "raw_source_values_not_assumed",
        "coordinate_system": "source_planar_xyz_not_geodetic_lat_lon",
        "evaluation_unit": "per_receiver_CAM_record_not_independent_hazard_incident",
        "cross_receiver_duplicate_handling": "preserved_raw",
        "limitations": [
            "CAM attacker=1 denotes per-message manipulated attributes, not a false physical hazard incident.",
            "Sender pseudonyms and sender IDs are not proof of independently enrolled authenticated vehicles.",
            "No incident_id, incident-level ground truth, or lat/lon is reconstructed.",
            "Reception of the same CAM at multiple receiver logs can duplicate a physical transmission.",
            "Dataset distribution copyright/license and declared split/subset must be verified independently.",
            "No cryptographic signatures or MACs are checked by this importer.",
        ],
    }
    summary_path.write_text(json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import verified VeReMi NextGen ZIP as unlumped CAM rows (no incident labels).")
    parser.add_argument("--archive", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--split", choices=("train", "validation", "test"), required=True)
    parser.add_argument("--attack-subset", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--max-json-files", type=int, default=20000)
    parser.add_argument("--max-entry-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=int, default=4 * 1024 * 1024 * 1024)
    args = parser.parse_args(argv)
    report = import_archive(
        Path(args.archive), Path(args.output_dir), expected_sha256=args.expected_sha256,
        split=args.split, attack_subset=args.attack_subset, release_tag=args.release_tag,
        max_json_files=args.max_json_files, max_entry_bytes=args.max_entry_bytes,
        max_total_bytes=args.max_total_bytes,
    )
    print(json.dumps({k: report[k] for k in (
        "status", "source_sha256_verified", "receiver_json_files",
        "received_cam_rows", "publication_ready",
    )}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
