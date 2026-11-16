"""Build a no-injection control paired with an offline replay scenario.

This is a synthetic control, not an independent dataset or vehicle-bus trace.
The control preserves the original recording; no extra frames are introduced.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

try:
    from .generate_can_replay_scenario import replay_scenario, OUT
except ImportError:
    from generate_can_replay_scenario import replay_scenario, OUT


def paired_control(raw: bytes, expected_sha256: str, scenario_id: str,
                   start: int, count: int, offset_us: int):
    attack, attack_manifest = replay_scenario(
        raw, expected_sha256, scenario_id, start, count, offset_us)
    reader = csv.DictReader(io.StringIO(attack.decode("utf-8"), newline=""), strict=True)
    if reader.fieldnames != list(OUT):
        raise ValueError("unexpected scenario schema")
    control_io = io.StringIO(newline="")
    writer = csv.writer(control_io, lineterminator="\n")
    writer.writerow(OUT)
    original = 0
    injected = 0
    for row in reader:
        if None in row or any(v is None for v in row.values()):
            raise ValueError("ragged scenario row")
        if row["synthetic_replay"] == "0":
            writer.writerow([row[key] for key in OUT])
            original += 1
        elif row["synthetic_replay"] == "1":
            injected += 1
        else:
            raise ValueError("unknown injection flag")
    if original != attack_manifest["original_frames"] or injected != count:
        raise ValueError("scenario counts inconsistent")
    control = control_io.getvalue().encode("utf-8")
    manifest = {
        "schema_version": 1,
        "simulation_only": True,
        "publication_ready": False,
        "control_type": "no_injection_original_recording",
        "comparison_limit": "different frame counts and post-recording observation exposure; not an equal-load or equal-duration control",
        "scenario_id": scenario_id,
        "source_recording_id": attack_manifest["source_recording_id"],
        "normalized_source_sha256": expected_sha256,
        "attack_sha256": hashlib.sha256(attack).hexdigest(),
        "control_sha256": hashlib.sha256(control).hexdigest(),
        "original_frames": original,
        "attack_injected_frames": injected,
        "control_injected_frames": 0,
        "replay_start_index": start,
        "replay_offset_us": offset_us,
    }
    return attack, control, manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--scenario-id", required=True)
    p.add_argument("--start", type=int, required=True)
    p.add_argument("--count", type=int, required=True)
    p.add_argument("--offset-us", type=int, required=True)
    p.add_argument("--attack-output", required=True)
    p.add_argument("--control-output", required=True)
    args = p.parse_args()
    if Path(args.attack_output).resolve() == Path(args.control_output).resolve():
        p.error("attack and control outputs must differ")
    attack, control, manifest = paired_control(
        Path(args.input).read_bytes(), args.expected_sha256,
        args.scenario_id, args.start, args.count, args.offset_us)
    Path(args.attack_output).write_bytes(attack)
    Path(args.control_output).write_bytes(control)
    Path(args.attack_output + ".pair.manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
