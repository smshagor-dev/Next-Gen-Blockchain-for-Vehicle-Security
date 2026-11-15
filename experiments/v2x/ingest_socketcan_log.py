"""Strict, label-free SocketCAN candump log ingestion for offline research.

Accepts only classic CAN lines of the form:
    (1700000000.000001) can0 123#DEADBEEF
or extended 29-bit identifiers with up to eight payload bytes.
No CAN-FD, RTR, error frames, timestamps inferred from local clocks,
vehicle actuation, attack labels, or dataset authenticity claims.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from pathlib import Path

LINE = re.compile(
    r"^\(([0-9]{1,12}\.[0-9]{1,9})\) ([A-Za-z0-9_.-]{1,32}) "
    r"([0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})#([0-9A-Fa-f]{0,16})$"
)
HEADER = ("recording_id", "seq", "timestamp_ns", "interface", "can_id_hex",
          "extended", "dlc", "data_hex")
MAX_BYTES = 64 * 1024 * 1024
MAX_FRAMES = 1000000
RECORDING_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def convert(raw: bytes, *, pinned_sha256: str, recording_id: str,
            expected_interface: str | None = None) -> tuple[bytes, dict]:
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("input exceeds 64 MiB limit")
    if not isinstance(pinned_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", pinned_sha256):
        raise ValueError("invalid external source SHA-256 pin")
    if sha256(raw) != pinned_sha256:
        raise ValueError("raw recording SHA-256 does not match external pin")
    if not isinstance(recording_id, str) or not RECORDING_ID.fullmatch(recording_id):
        raise ValueError("invalid recording ID")
    if expected_interface is not None and (
            not isinstance(expected_interface, str) or
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", expected_interface)):
        raise ValueError("invalid expected interface")
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise ValueError("candump must be ASCII") from exc
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(HEADER)
    count, previous_ns, first_ns = 0, None, None
    for line_number, line in enumerate(text.splitlines(), 1):
        if count >= MAX_FRAMES:
            raise ValueError("frame count exceeds limit")
        match = LINE.fullmatch(line)
        if not match:
            raise ValueError(f"unsupported or malformed classic CAN frame at line {line_number}")
        stamp, interface, identifier, data = match.groups()
        if expected_interface is not None and interface != expected_interface:
            raise ValueError(f"unexpected interface at line {line_number}")
        seconds, fraction = stamp.split(".")
        timestamp_ns = int(seconds) * 1000000000 + int(fraction.ljust(9, "0"))
        if previous_ns is not None and timestamp_ns < previous_ns:
            raise ValueError(f"nonchronological timestamp at line {line_number}")
        previous_ns = timestamp_ns
        if first_ns is None:
            first_ns = timestamp_ns
        if len(data) % 2:
            raise ValueError(f"odd-length CAN payload at line {line_number}")
        identifier_value = int(identifier, 16)
        extended = len(identifier) == 8
        if (extended and identifier_value > 0x1FFFFFFF) or (
                not extended and identifier_value > 0x7FF):
            raise ValueError(f"out-of-range CAN identifier at line {line_number}")
        writer.writerow((recording_id, count, timestamp_ns, interface,
                         identifier.upper(), int(extended), len(data) // 2,
                         data.upper()))
        count += 1
    if not count:
        raise ValueError("empty recording cannot support frame-level analysis")
    normalized = output.getvalue().encode("ascii")
    report = {
        "schema_version": 1,
        "status": "offline_socketcan_classic_normalization",
        "publication_ready": False,
        "recording_id": recording_id,
        "source_sha256": sha256(raw),
        "normalized_sha256": sha256(normalized),
        "frames": count,
        "first_timestamp_ns": first_ns,
        "last_timestamp_ns": previous_ns,
        "expected_interface": expected_interface,
        "limitations": [
            "Operator-provided SHA-256 pin does not establish publisher authenticity or a trusted capture clock.",
            "No vehicle identity, attack labels, independent ground truth or recording-level split is inferred.",
            "Classic CAN only: CAN-FD, RTR, error and unsupported candump formats are rejected.",
            "This offline parser never transmits frames or authorizes vehicle actuation.",
        ],
    }
    return normalized, report


def main() -> None:
    p = argparse.ArgumentParser(description="Normalize externally pinned classic SocketCAN logs")
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--raw-sha256", required=True)
    p.add_argument("--recording-id", required=True)
    p.add_argument("--interface")
    p.add_argument("--output-csv", required=True, type=Path)
    p.add_argument("--output-report", required=True, type=Path)
    args = p.parse_args()
    for output in (args.output_csv, args.output_report):
        if output.exists():
            p.error("refuse to overwrite an existing research artifact")
    normalized, report = convert(
        args.input.read_bytes(), pinned_sha256=args.raw_sha256,
        recording_id=args.recording_id, expected_interface=args.interface)
    # Write after all validation; no partial outputs on malformed inputs.
    args.output_csv.write_bytes(normalized)
    args.output_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8")
    print(json.dumps({"frames": report["frames"], "normalized_sha256": report["normalized_sha256"],
                      "publication_ready": False}))


if __name__ == "__main__":
    main()
