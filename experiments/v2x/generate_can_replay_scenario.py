"""Offline, deterministic CAN replay attack scenario generator (simulation only).

Input is normalized output of normalize_can_recording.py, not a vehicle bus.
Injected events are synthetic intervention labels, never publisher ground truth.
"""
import argparse
import csv
import hashlib
import io
import json
import re
from pathlib import Path

FIELDS = ("recording_id", "frame_index", "timestamp_us", "can_id", "dlc", "data_hex")
OUT = ("scenario_id", "event_index", "timestamp_us", "can_id", "dlc", "data_hex", "source_frame_index", "synthetic_replay")
MAX_INPUT = 64 * 1024 * 1024
MAX_FRAMES = 1000000


def replay_scenario(raw: bytes, expected_sha256: str, scenario_id: str,
                    start: int, count: int, offset_us: int) -> tuple[bytes, dict]:
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT:
        raise ValueError("bounded normalized bytes required")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "") or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("normalized source digest mismatch")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", scenario_id or ""):
        raise ValueError("invalid scenario id")
    if any(type(x) is not int for x in (start, count, offset_us)) or start < 0 or not 1 <= count <= MAX_FRAMES or offset_us <= 0:
        raise ValueError("invalid replay selection or offset")
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True)
        if reader.fieldnames != list(FIELDS):
            raise ValueError("exact normalized schema required")
        frames = []
        prev = -1
        recording = None
        for row in reader:
            if len(frames) >= MAX_FRAMES or None in row or any(row.get(k) is None for k in FIELDS):
                raise ValueError("invalid frame count or ragged row")
            if not re.fullmatch(r"[0-9]+", row["timestamp_us"]) or not re.fullmatch(r"[0-9]+", row["frame_index"]):
                raise ValueError("invalid frame timestamp or index")
            ts = int(row["timestamp_us"])
            if ts < prev or int(row["frame_index"]) != len(frames) or ts > 2**63 - 1:
                raise ValueError("nonmonotonic timestamps or frame index")
            if recording is None:
                recording = row["recording_id"]
            if row["recording_id"] != recording:
                raise ValueError("mixed recording IDs")
            if not re.fullmatch(r"[0-9A-F]{1,8}", row["can_id"]) or int(row["can_id"], 16) > 0x1FFFFFFF:
                raise ValueError("invalid CAN id")
            if not re.fullmatch(r"[0-9]+", row["dlc"]) or int(row["dlc"]) not in (*range(9), 12, 16, 20, 24, 32, 48, 64):
                raise ValueError("invalid byte length")
            if len(row["data_hex"]) != 2 * int(row["dlc"]) or not re.fullmatch(r"[0-9A-F]*", row["data_hex"]):
                raise ValueError("invalid payload")
            frames.append(row)
            prev = ts
    except (UnicodeError, csv.Error) as exc:
        raise ValueError("malformed normalized CSV") from exc
    if start + count > len(frames):
        raise ValueError("replay window outside recording")
    selected = frames[start:start + count]
    base = int(selected[0]["timestamp_us"])
    last = int(frames[-1]["timestamp_us"])
    if last + offset_us + int(selected[-1]["timestamp_us"]) - base > 2**63 - 1:
        raise ValueError("timestamp overflow")
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(OUT)
    for idx, row in enumerate(frames):
        writer.writerow((scenario_id, idx, row["timestamp_us"], row["can_id"], row["dlc"], row["data_hex"], row["frame_index"], 0))
    for i, row in enumerate(selected):
        writer.writerow((scenario_id, len(frames) + i, last + offset_us + int(row["timestamp_us"]) - base,
                         row["can_id"], row["dlc"], row["data_hex"], row["frame_index"], 1))
    output = out.getvalue().encode()
    return output, {"schema_version": 1, "simulation_only": True, "publication_ready": False,
                    "scenario_id": scenario_id, "source_recording_id": recording,
                    "normalized_source_sha256": expected_sha256,
                    "scenario_sha256": hashlib.sha256(output).hexdigest(),
                    "original_frames": len(frames), "synthetic_replay_frames": count,
                    "replay_start_index": start, "replay_offset_us": offset_us}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--offset-us", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    data, report = replay_scenario(Path(args.input).read_bytes(), args.expected_sha256,
                                   args.scenario_id, args.start, args.count, args.offset_us)
    Path(args.output).write_bytes(data)
    Path(args.output + ".manifest.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
