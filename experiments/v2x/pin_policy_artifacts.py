"""Pre-run executable/config digest pinning for paired V2X policy trials.

Integrity only: hashing source/config cannot prove that a given executable ran.
The operator must pin this manifest BEFORE trials using an external timestamp.
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
from pathlib import Path

from capture_export_producer import canonical, create_once
from verify_capture_receipt_pair import load_strict_json

FIELDS = {"schema_version", "baseline_executable_sha256",
          "candidate_executable_sha256", "baseline_config_sha256",
          "candidate_config_sha256", "baseline_policy_name",
          "candidate_policy_name", "trial_manifest_sha256"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_pin(trial_manifest: bytes, baseline_executable: bytes,
              candidate_executable: bytes, baseline_config: bytes,
              candidate_config: bytes, baseline_name: str,
              candidate_name: str) -> bytes:
    if not all(isinstance(n, str) and n.strip() for n in (baseline_name, candidate_name)):
        raise ValueError("policy names must be nonempty")
    if baseline_name == candidate_name:
        raise ValueError("baseline and candidate policy names must differ")
    if any(not isinstance(x, bytes) or not x for x in (
            trial_manifest, baseline_executable, candidate_executable,
            baseline_config, candidate_config)):
        raise ValueError("all executable/configuration artifacts must be nonempty bytes")
    manifest = load_strict_json(trial_manifest)
    if manifest.get("baseline_name") != baseline_name or manifest.get("candidate_name") != candidate_name:
        raise ValueError("policy names do not match trial manifest")
    return canonical({
        "schema_version": 1,
        "trial_manifest_sha256": sha(trial_manifest),
        "baseline_executable_sha256": sha(baseline_executable),
        "candidate_executable_sha256": sha(candidate_executable),
        "baseline_config_sha256": sha(baseline_config),
        "candidate_config_sha256": sha(candidate_config),
        "baseline_policy_name": baseline_name,
        "candidate_policy_name": candidate_name,
    })


def verify_pin(pin_bytes: bytes, pinned_digest: str, trial_manifest: bytes,
               baseline_executable: bytes, candidate_executable: bytes,
               baseline_config: bytes, candidate_config: bytes) -> dict:
    if not isinstance(pinned_digest, str) or not hmac.compare_digest(sha(pin_bytes), pinned_digest):
        raise ValueError("external executable pin mismatch")
    data = load_strict_json(pin_bytes)
    if set(data) != FIELDS or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("invalid executable pin schema")
    expected = build_pin(
        trial_manifest, baseline_executable, candidate_executable,
        baseline_config, candidate_config,
        data["baseline_policy_name"], data["candidate_policy_name"])
    if not hmac.compare_digest(expected, pin_bytes):
        raise ValueError("policy artifact digest or canonical pin mismatch")
    return {
        "pin_verified": True, "executable_pin_sha256": pinned_digest,
        "publication_ready": False,
        "limitation": "Artifact digests do not prove executed binary, runtime configuration, independent witness, or pre-run external timestamp."
    }


def main():
    parser = argparse.ArgumentParser(description="Pre-run policy artifact pin; not an execution attestation")
    parser.add_argument("command", choices=("create", "verify"))
    for name in ("trial-manifest", "baseline-executable", "candidate-executable",
                 "baseline-config", "candidate-config"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--baseline-name")
    parser.add_argument("--candidate-name")
    parser.add_argument("--pin", required=True, type=Path)
    parser.add_argument("--pinned-digest")
    args = parser.parse_args()
    inputs = [getattr(args, n).read_bytes() for n in (
        "trial_manifest", "baseline_executable", "candidate_executable",
        "baseline_config", "candidate_config")]
    if args.command == "create":
        data = build_pin(*inputs, args.baseline_name, args.candidate_name)
        create_once(args.pin, data)
        print(json.dumps({"pin_sha256": sha(data), "external_prerun_pin_required": True,
                          "publication_ready": False}))
    else:
        if not args.pinned_digest:
            parser.error("verify requires --pinned-digest")
        print(json.dumps(verify_pin(args.pin.read_bytes(), args.pinned_digest, *inputs)))


if __name__ == "__main__":
    main()
