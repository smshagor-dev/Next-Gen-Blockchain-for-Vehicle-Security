"""Fail-closed binding of executed simulator stdout to the captured incident stream.

Only for simulations that emit the EXACT capture CSV on stdout. This does not
prove physical sensing, independent policy execution, or independent truth.
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
from pathlib import Path

from capture_export_producer import canonical, verify_manifest
from pin_policy_artifacts import verify_pin, sha
from verify_capture_receipt_pair import load_strict_json, verify_pair
from paired_signed_capture_analysis import verify_assignment

EXECUTION_FIELDS = {
    "schema_version", "arm", "policy_name", "trial_manifest_sha256",
    "artifact_pin_sha256", "executable_sha256", "config_sha256",
    "command", "process_pid_observed", "started_utc_local_clock",
    "duration_ms_local_clock", "returncode", "stdout_sha256",
    "stderr_sha256", "stdout_bytes", "stderr_bytes",
    "publication_ready", "limitations",
}


def verify_execution_capture(manifest_bytes: bytes, world_bytes: bytes,
                             manifest_pin: str, artifact_pin_bytes: bytes,
                             artifact_pin_sha256: str,
                             baseline_executable: bytes, candidate_executable: bytes,
                             baseline_config: bytes, candidate_config: bytes,
                             execution_receipt_bytes: bytes, capture_bytes: bytes,
                             export_receipt_bytes: bytes, interval_receipt_bytes: bytes,
                             assignment_receipt_bytes: bytes,
                             export_key: bytes, interval_key: bytes,
                             assignment_key: bytes, expected_arm: str) -> dict:
    """Require receipt stdout digest and size to match signed capture exactly."""
    if expected_arm not in ("baseline", "candidate"):
        raise ValueError("unknown expected policy arm")
    manifest = verify_manifest(manifest_bytes, world_bytes, manifest_pin)
    verify_pin(artifact_pin_bytes, artifact_pin_sha256, manifest_bytes,
               baseline_executable, candidate_executable,
               baseline_config, candidate_config)
    receipt = load_strict_json(execution_receipt_bytes)
    if set(receipt) != EXECUTION_FIELDS or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1:
        raise ValueError("invalid execution receipt schema")
    if receipt["arm"] != expected_arm or receipt["policy_name"] != manifest[expected_arm + "_name"]:
        raise ValueError("execution receipt arm/policy mismatch")
    executable = baseline_executable if expected_arm == "baseline" else candidate_executable
    config = baseline_config if expected_arm == "baseline" else candidate_config
    for key, expected in (
        ("trial_manifest_sha256", sha(manifest_bytes)),
        ("artifact_pin_sha256", artifact_pin_sha256),
        ("executable_sha256", sha(executable)),
        ("config_sha256", sha(config)),
        ("stdout_sha256", sha(capture_bytes)),
    ):
        if not isinstance(receipt[key], str) or not hmac.compare_digest(receipt[key], expected):
            raise ValueError("execution receipt mismatch: " + key)
    if type(receipt["stdout_bytes"]) is not int or receipt["stdout_bytes"] != len(capture_bytes):
        raise ValueError("executed stdout size differs from captured evidence")
    if type(receipt["returncode"]) is not int or receipt["returncode"] != 0:
        raise ValueError("simulation process did not succeed")
    if receipt["publication_ready"] is not False:
        raise ValueError("execution receipt cannot assert publication readiness")
    if not isinstance(receipt["command"], list) or len(receipt["command"]) != 2 or any(
            not isinstance(x, str) or not x for x in receipt["command"]):
        raise ValueError("invalid execution command evidence")
    if not isinstance(receipt["limitations"], list) or not receipt["limitations"]:
        raise ValueError("execution limitations missing")
    verify_assignment(assignment_receipt_bytes, manifest, manifest_pin,
                      capture_bytes, expected_arm, assignment_key)
    report = verify_pair(world_bytes, capture_bytes, manifest_bytes, manifest_pin,
                         export_receipt_bytes, interval_receipt_bytes,
                         export_key, interval_key)
    return {
        "schema_version": 1, "publication_ready": False,
        "arm": expected_arm, "policy_name": receipt["policy_name"],
        "trial_manifest_sha256": sha(manifest_bytes),
        "artifact_pin_sha256": artifact_pin_sha256,
        "execution_receipt_sha256": sha(execution_receipt_bytes),
        "capture_sha256": sha(capture_bytes),
        "capture_rows_integrity_checked": True,
        "incident_counts": {k: report[k] for k in ("tp", "fp", "tn", "fn")},
        "limitations": [
            "Stdout digest equality only establishes a byte-level link to the operator-generated execution receipt.",
            "The execution receipt is not signed by an independent process witness or trusted hardware.",
            "No independent physical sensor uptime, vehicle actuation safety, or authentic external labels verified.",
        ],
    }


def main():
    p = argparse.ArgumentParser(description="Bind simulation stdout to signed capture; NOT independent attestation")
    for name in ("manifest", "world", "artifact-pin", "baseline-executable",
                 "candidate-executable", "baseline-config", "candidate-config",
                 "execution-receipt", "capture", "export-receipt", "interval-receipt",
                 "assignment-receipt", "export-key", "interval-key", "assignment-key",
                 "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--manifest-pin", required=True)
    p.add_argument("--artifact-pin-sha256", required=True)
    p.add_argument("--arm", choices=("baseline", "candidate"), required=True)
    a = p.parse_args()
    def read(name):
        return getattr(a, name.replace("-", "_")).read_bytes()
    report = verify_execution_capture(
        *(read(name) for name in ("manifest", "world")), a.manifest_pin,
        read("artifact-pin"), a.artifact_pin_sha256,
        *(read(name) for name in ("baseline-executable", "candidate-executable",
                                  "baseline-config", "candidate-config",
                                  "execution-receipt", "capture", "export-receipt",
                                  "interval-receipt", "assignment-receipt",
                                  "export-key", "interval-key", "assignment-key")),
        a.arm)
    from capture_export_producer import create_once
    payload = canonical(report)
    create_once(a.output, payload)
    print(json.dumps({"verification_sha256": sha(payload), "publication_ready": False}))


if __name__ == "__main__":
    main()
