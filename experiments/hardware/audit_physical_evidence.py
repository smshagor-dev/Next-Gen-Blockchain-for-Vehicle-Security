"""Fail-closed structural audit of external *non-actuating dummy-load* HIL evidence.

A PASS only means the submitted measurement files are structurally consistent
and match pinned digests. Self-supplied operator/witness IDs and CSV samples do
NOT establish physical measurement authenticity, independent hardwired E-stop
operation, vehicle safety or functional-safety certification. No GPIO/CAN/ECU
I/O exists in this module.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import re
from pathlib import Path

CASES = tuple(f"HIL-{i:02d}" for i in range(1, 11))
SCHEMA = "omni-non-actuating-bench-evidence-v1"
SHA = re.compile(r"^[a-f0-9]{64}$")
SESSION = re.compile(r"^[A-Za-z0-9_.-]{4,80}$")
COLUMNS = ("elapsed_sec", "hardwired_estop_asserted", "dummy_load_enabled", "network_link_available")
MAX_BYTES = 20 * 1024 * 1024
MAX_SAMPLES = 500_000

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def _member(root: Path, name: object) -> Path:
    if (not isinstance(name, str) or not name or name.startswith(("/", "\\"))
            or "\\" in name or ":" in name):
        raise ValueError("invalid artifact path")
    parts = Path(name).parts
    if any(p in ("..", ".") for p in parts):
        raise ValueError("path traversal in evidence artifact")
    path = root.joinpath(*parts)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("evidence artifact missing/linked/oversized")
    # No nested symlink may change artifact provenance.
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("evidence artifact escapes session directory")
    return path

def _pinned(root: Path, entry: object) -> tuple[Path, str]:
    if (not isinstance(entry, dict) or set(entry) != {"path", "sha256"}
            or not isinstance(entry["sha256"], str)
            or not SHA.fullmatch(entry["sha256"])):
        raise ValueError("unverified evidence digest declaration")
    path = _member(root, entry["path"])
    actual = _sha256(path)
    if not hmac.compare_digest(actual, entry["sha256"]):
        raise ValueError("evidence artifact digest mismatch")
    return path, actual

def _trace(path: Path) -> dict:
    if path.stat().st_size == 0:
        raise ValueError("empty measurement")
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, strict=True)
        if (reader.fieldnames is None or tuple(reader.fieldnames) != COLUMNS):
            raise ValueError("measurement columns do not match frozen schema")
        prev = None
        count = 0
        stopped_points = 0
        link_down_points = 0
        unsafe_reenergization = False
        has_off_after_stop = False
        first_stop = None
        first_off_after_stop = None
        stop_off_seen = False
        for row in reader:
            count += 1
            if count > MAX_SAMPLES:
                raise ValueError("measurement has excessive samples")
            if (None in row or any(row.get(k) is None for k in COLUMNS)
                    or any(row[k] not in ("0", "1") for k in COLUMNS[1:])):
                raise ValueError("malformed or non-boolean instrument measurement")
            try:
                t = float(row["elapsed_sec"])
            except ValueError as exc:
                raise ValueError("invalid instrument time") from exc
            if not math.isfinite(t) or t < 0 or (prev is not None and t <= prev):
                raise ValueError("instrument time not finite, monotonic and nonnegative")
            prev = t
            stop = row["hardwired_estop_asserted"] == "1"
            output_on = row["dummy_load_enabled"] == "1"
            link_up = row["network_link_available"] == "1"
            if not link_up:
                link_down_points += 1
            if stop:
                stopped_points += 1
                if first_stop is None:
                    first_stop = t
                if not output_on:
                    stop_off_seen = True
                    has_off_after_stop = True
                    if first_off_after_stop is None:
                        first_off_after_stop = t
                elif stop_off_seen:
                    unsafe_reenergization = True
            elif first_stop is not None:
                # Only the first stop assertion is measured; a later assertion
                # would require a separate test session for unambiguous latency.
                raise ValueError("stop assertion released during trace; isolate trial")
        if count < 3:
            raise ValueError("insufficient measurement samples")
        if unsafe_reenergization:
            raise ValueError("dummy load re-energized while hardwired stop asserted")
        return {
            "samples": count,
            "stop_samples": stopped_points,
            "network_down_samples": link_down_points,
            "observed_dummy_load_off_after_stop": has_off_after_stop,
            "sampled_stop_to_off_ms": (
                round(1000 * (first_off_after_stop - first_stop), 6)
                if first_stop is not None and first_off_after_stop is not None
                else None
            ),
            "instrument_sampling_latency_uncertainty_not_bounded": True,
        }

def audit(root: Path, manifest: Path, output: Path) -> dict:
    root = Path(root).resolve()
    manifest = Path(manifest)
    if (not root.is_dir() or manifest.is_symlink()
            or not manifest.is_file() or manifest.stat().st_size > 1024 * 1024):
        raise ValueError("invalid session root/manifest")
    if not manifest.resolve().is_relative_to(root):
        raise ValueError("manifest must be inside evidence root")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError("unknown evidence schema")
    fields = ("session_id", "apparatus_id", "operator_id", "witness_id",
              "firmware_sha256", "bench_configuration", "instrument")
    if any(not isinstance(data.get(k), str) or not data[k].strip() for k in fields):
        raise ValueError("missing session/instrument/witness provenance")
    if any(not SESSION.fullmatch(data[k]) for k in fields[:4]):
        raise ValueError("invalid session identifier")
    if data["operator_id"] == data["witness_id"]:
        raise ValueError("operator and witness must be distinct declared persons")
    if not SHA.fullmatch(data["firmware_sha256"]):
        raise ValueError("missing pinned firmware source identity")
    if data["bench_configuration"] != "isolated_dummy_load_no_vehicle":
        raise ValueError("live vehicle testing is not accepted by this audit")
    _, calibration_digest = _pinned(root, data.get("calibration"))
    cases = data.get("cases")
    if (not isinstance(cases, list) or len(cases) != len(CASES)
            or {c.get("id") for c in cases if isinstance(c, dict)} != set(CASES)):
        raise ValueError("every required HIL-01..HIL-10 case must be present")
    rows = []
    for c in cases:
        if not isinstance(c, dict) or set(c) != {"id", "capture", "witness_id"}:
            raise ValueError("unexpected/missing HIL case evidence fields")
        if c["witness_id"] != data["witness_id"]:
            raise ValueError("inconsistent declared witness identity")
        trace_path, digest = _pinned(root, c["capture"])
        measured = _trace(trace_path)
        if c["id"] in ("HIL-02", "HIL-03", "HIL-09", "HIL-10"):
            if not measured["observed_dummy_load_off_after_stop"]:
                raise ValueError(f"{c['id']}: no sampled independent-stop-to-off transition")
        if c["id"] == "HIL-03" and not measured["network_down_samples"]:
            raise ValueError("HIL-03 lacks captured network loss")
        rows.append({"case_id": c["id"], "sha256": digest, **measured})
    result = {
        "status": "digital_artifact_integrity_checked_not_physical_validation",
        "session_id": data["session_id"],
        "source_manifest_sha256": _sha256(manifest),
        "calibration_sha256": calibration_digest,
        "required_case_count": len(rows),
        "cases": sorted(rows, key=lambda x: x["case_id"]),
        "all_cases_structurally_audited": True,
        "witness_identity_independently_verified": False,
        "instrument_capture_authenticity_independently_verified": False,
        "external_hardwired_estop_physically_verified": False,
        "vehicle_safety_certified": False,
        "physical_hil_validated": False,
        "publication_ready": False,
        "limitations": [
            "A CSV/digest may be self-generated; physical source cannot be inferred.",
            "No independent calibration attestation or cryptographic witness identity was verified.",
            "Sampled stop latency is neither an upper bound nor proof of hardwired independence.",
            "A qualified real physical bench review is required separately.",
        ],
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence-dir", required=True, type=Path)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    a = p.parse_args()
    r = audit(a.evidence_dir, a.manifest, a.report)
    print(json.dumps({k:r[k] for k in (
        "status", "required_case_count", "physical_hil_validated", "publication_ready"
    )}, sort_keys=True))

if __name__ == "__main__":
    main()
