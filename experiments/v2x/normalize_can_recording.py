"""Fail-closed normalization of externally sourced CAN frame CSV.

This adapter never assigns attack/ground-truth labels, never connects to a CAN
interface, and never treats fixture inputs as authentic data. An operator must
pin a publisher-sourced raw archive and record its license and capture lineage.
The raw CSV schema is explicit: timestamp_us,can_id,dlc,data_hex. IDs are
canonical hexadecimal without 0x; data_hex has exactly 2*dlc digits.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
import re
from pathlib import Path

RAW_FIELDS = ("timestamp_us", "can_id", "dlc", "data_hex")
OUT_FIELDS = ("recording_id", "frame_index", *RAW_FIELDS)
HEX = re.compile(r"^[0-9A-Fa-f]+$")
MAX_BYTES = 64 * 1024 * 1024
MAX_ROWS = 1000000


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize(raw: bytes, *, expected_sha256: str, recording_id: str,
              frame_limit: int = MAX_ROWS) -> tuple[bytes, dict]:
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("raw source exceeds byte bound")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("invalid pinned SHA-256")
    if digest(raw) != expected_sha256:
        raise ValueError("raw source hash differs from external pin")
    if not isinstance(recording_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", recording_id):
        raise ValueError("invalid source recording identifier")
    if type(frame_limit) is not int or not 1 <= frame_limit <= MAX_ROWS:
        raise ValueError("invalid frame bound")
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("source encoding is not UTF-8") from exc
    reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
    if reader.fieldnames != list(RAW_FIELDS):
        raise ValueError("CAN source requires exact unlabeled frame schema")
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(OUT_FIELDS)
    last_us = -1
    count = 0
    classic = fd = 0
    for row in reader:
        if count >= frame_limit:
            raise ValueError("source exceeds maximum frame count")
        if None in row or set(row) != set(RAW_FIELDS) or any(
                not isinstance(row[k], str) or (not row[k] and k != "data_hex")
                for k in RAW_FIELDS):
            raise ValueError("malformed CAN frame row")
        timestamp, can_id, dlc, payload = (
            row["timestamp_us"], row["can_id"], row["dlc"], row["data_hex"])
        if not timestamp.isascii() or not timestamp.isdecimal() or (
                len(timestamp) > 1 and timestamp.startswith("0")):
            raise ValueError("timestamp must be canonical integer microseconds")
        micros = int(timestamp)
        if micros < last_us or micros > 2**63 - 1:
            raise ValueError("nonmonotonic or overflowing timestamp")
        last_us = micros
        if not HEX.fullmatch(can_id) or len(can_id) > 8 or int(can_id, 16) > 0x1FFFFFFF:
            raise ValueError("invalid 11/29-bit CAN identifier")
        if not dlc.isascii() or not dlc.isdecimal() or len(dlc) > 2 or (
                len(dlc) > 1 and dlc.startswith("0")):
            raise ValueError("invalid DLC")
        length = int(dlc)
        # The adapter accepts CAN FD payload sizes as actual byte lengths,
        # not raw DLC *codes* 9..15; no automatic FD DLC conversion.
        if length not in (*range(0, 9), 12, 16, 20, 24, 32, 48, 64):
            raise ValueError("unsupported CAN/CAN-FD byte length")
        if len(payload) != 2 * length or (payload and not HEX.fullmatch(payload)):
            raise ValueError("payload does not match declared byte length")
        writer.writerow((recording_id, count, str(micros), f"{int(can_id,16):X}",
                         str(length), payload.upper()))
        count += 1
        if length <= 8:
            classic += 1
        else:
            fd += 1
    if not count:
        raise ValueError("empty recording cannot establish coverage")
    normalized = output.getvalue().encode("utf-8")
    report = {
        "schema_version": 1, "publication_ready": False,
        "source_recording_id": recording_id,
        "raw_sha256": expected_sha256,
        "normalized_sha256": digest(normalized),
        "frame_count": count, "classic_payload_frames": classic,
        "fd_payload_frames": fd,
        "first_timestamp_us": None,  # caller must not infer capture start from frames
        "capture_complete": False,
        "label_provenance_verified": False,
        "limitations": [
            "Input bytes are externally pinned, not independently authenticated publisher data.",
            "No attack labels, scenario truth, clock calibration, missing-frame detection or session authentication inferred.",
            "This is a normalized offline frame export, not live CAN capture or ECU command authorization.",
            "Capture start/end, sensor uptime, independent ground truth and license require external records.",
        ],
    }
    return normalized, report


def main() -> None:
    p = argparse.ArgumentParser(description="Normalize operator-pinned offline CAN CSV without inferring labels")
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--raw-sha256", required=True)
    p.add_argument("--recording-id", required=True)
    p.add_argument("--normalized", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    if a.normalized.exists() or a.report.exists():
        p.error("refuse to overwrite an existing normalized artifact")
    normalized, report = normalize(a.raw.read_bytes(), expected_sha256=a.raw_sha256,
                                   recording_id=a.recording_id)
    a.normalized.write_bytes(normalized)
    a.report.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"normalized_sha256": report["normalized_sha256"],
                      "frame_count": report["frame_count"], "publication_ready": False}))


if __name__ == "__main__":
    main()
