"""Construct equal-frame-count, equal-timestamp CAN sham controls offline.

A donor recording MUST be independently established benign outside this program.
This tool validates bytes and separation, not donor truth or source authenticity.
No hardware interface is opened.
"""
import csv
import hashlib
import io
import re

try:
    from .generate_can_replay_scenario import replay_scenario, OUT
except ImportError:
    from generate_can_replay_scenario import replay_scenario, OUT


def _rows(raw):
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
    if reader.fieldnames != list(OUT):
        raise ValueError("unexpected scenario schema")
    rows = list(reader)
    if any(None in row or any(v is None for v in row.values()) for row in rows):
        raise ValueError("ragged scenario")
    return rows


def matched_sham_control(source: bytes, source_sha256: str, donor: bytes,
                         donor_sha256: str, scenario_id: str, start: int,
                         count: int, offset_us: int, donor_start: int = 0):
    """Return attack CSV, matched sham CSV, and provenance manifest.

    Donor is a separately pinned normalized recording. The sham appends donor
    frames at EXACTLY the injected replay timestamps. This controls frame
    count and observation horizon, not payload distributions or causal effects.
    """
    if source_sha256 == donor_sha256 or source == donor:
        raise ValueError("independent donor recording required")
    if type(donor_start) is not int or donor_start < 0:
        raise ValueError("invalid donor start")
    attack, attack_meta = replay_scenario(
        source, source_sha256, scenario_id, start, count, offset_us)
    donor_scenario, donor_meta = replay_scenario(
        donor, donor_sha256, scenario_id, donor_start, count, 1)
    if (not attack_meta["source_recording_id"] or
            not donor_meta["source_recording_id"] or
            attack_meta["source_recording_id"] == donor_meta["source_recording_id"]):
        raise ValueError("source and donor recording IDs must differ")
    attack_rows = _rows(attack)
    donor_rows = _rows(donor_scenario)
    n = attack_meta["original_frames"]
    dn = donor_meta["original_frames"]
    if len(attack_rows) != n + count or len(donor_rows) != dn + count:
        raise ValueError("unexpected frame counts")
    original = attack_rows[:n]
    injected = attack_rows[n:]
    if any(row["synthetic_replay"] != "0" for row in original):
        raise ValueError("invalid original flags")
    if any(row["synthetic_replay"] != "1" for row in injected):
        raise ValueError("invalid replay flags")
    selected = donor_rows[donor_start:donor_start + count]
    if len(selected) != count or any(row["synthetic_replay"] != "0" for row in selected):
        raise ValueError("invalid donor window")
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(OUT)
    for row in original:
        writer.writerow([row[key] for key in OUT])
    for index, (injected_row, donor_row) in enumerate(zip(injected, selected)):
        writer.writerow([
            scenario_id, n + index, injected_row["timestamp_us"],
            donor_row["can_id"], donor_row["dlc"], donor_row["data_hex"],
            donor_row["source_frame_index"], 0
        ])
    control = output.getvalue().encode("utf-8")
    control_rows = _rows(control)
    if (len(control_rows) != len(attack_rows) or
            [r["timestamp_us"] for r in control_rows] !=
            [r["timestamp_us"] for r in attack_rows]):
        raise ValueError("matched horizon/frame-count invariant failed")
    manifest = {
        "schema_version": 1,
        "simulation_only": True,
        "publication_ready": False,
        "control_type": "externally_verified_benign_donor_required",
        "donor_benign_status": "NOT_VERIFIED_BY_THIS_TOOL",
        "comparability_limit": "equal timestamps/frame counts only; payload distributions and donor benignness not controlled",
        "scenario_id": scenario_id,
        "source_recording_id": attack_meta["source_recording_id"],
        "donor_recording_id": donor_meta["source_recording_id"],
        "source_sha256": source_sha256,
        "donor_sha256": donor_sha256,
        "attack_sha256": hashlib.sha256(attack).hexdigest(),
        "control_sha256": hashlib.sha256(control).hexdigest(),
        "total_frames_each": len(attack_rows),
        "appended_frames_each": count,
        "donor_start_index": donor_start,
        "replay_start_index": start,
        "replay_offset_us": offset_us,
        "last_timestamp_us": attack_rows[-1]["timestamp_us"],
    }
    return attack, control, manifest
