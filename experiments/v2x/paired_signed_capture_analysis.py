"""Matched incident comparison of independently sourced world labels and two signed captures.

Receipts bind bytes to claimed policy assignments, NOT actual executed policy,
trusted ground truth, cluster independence, or physical observation coverage.
Never interpret synthetic tests or an exact McNemar p-value as published evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path

from capture_export_producer import canonical, verify_manifest
from join_world_incidents import (CAPTURE_COLUMNS, WORLD_COLUMNS, digest,
                                  rows_from_bytes)
from verify_capture_receipt_pair import load_strict_json, verify_pair

ASSIGNMENT_FIELDS = frozenset(("schema_version", "manifest_sha256", "capture_sha256",
                               "arm", "policy_name", "hmac_sha256"))
ARMS = ("baseline", "candidate")


def assignment_payload(receipt: dict) -> bytes:
    if not isinstance(receipt, dict) or set(receipt) != ASSIGNMENT_FIELDS:
        raise ValueError("invalid policy assignment receipt schema")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1:
        raise ValueError("unsupported assignment schema version")
    if any(not isinstance(receipt[k], str) or not receipt[k]
           for k in ("manifest_sha256", "capture_sha256", "arm", "policy_name")):
        raise ValueError("invalid policy assignment fields")
    return canonical({k: receipt[k] for k in ASSIGNMENT_FIELDS if k != "hmac_sha256"})


def sign_assignment(manifest_bytes: bytes, world_bytes: bytes, pin: str,
                    capture_bytes: bytes, arm: str, key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("assignment signing key is too short")
    manifest = verify_manifest(manifest_bytes, world_bytes, pin)
    if arm not in ARMS:
        raise ValueError("unsupported policy arm")
    receipt = {"schema_version": 1, "manifest_sha256": pin,
               "capture_sha256": digest(capture_bytes), "arm": arm,
               "policy_name": manifest[arm + "_name"], "hmac_sha256": ""}
    receipt["hmac_sha256"] = hmac.new(
        key, assignment_payload(receipt), hashlib.sha256).hexdigest()
    return canonical(receipt)


def verify_assignment(data: bytes, manifest: dict, pin: str, capture: bytes,
                      expected_arm: str, key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("assignment verification key is too short")
    receipt = load_strict_json(data)
    signed = assignment_payload(receipt)
    if not isinstance(receipt["hmac_sha256"], str):
        raise ValueError("invalid assignment HMAC")
    expected = hmac.new(key, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, receipt["hmac_sha256"]):
        raise ValueError("policy assignment HMAC mismatch")
    if receipt["arm"] != expected_arm or receipt["policy_name"] != manifest[expected_arm + "_name"]:
        raise ValueError("policy assignment does not match preselected arm")
    if not hmac.compare_digest(receipt["manifest_sha256"], pin) or not hmac.compare_digest(
            receipt["capture_sha256"], digest(capture)):
        raise ValueError("policy assignment does not bind trial and capture")


def _predictions(capture: bytes) -> set[str]:
    return {row["incident_id"] for row in rows_from_bytes(
        capture, CAPTURE_COLUMNS, allow_empty=True) if row["alert_relayed"] == "1"}


def _metrics(rows: list[dict], field: str) -> dict:
    tp = sum(r["truth"] == 1 and r[field] == 1 for r in rows)
    tn = sum(r["truth"] == 0 and r[field] == 0 for r in rows)
    fp = sum(r["truth"] == 0 and r[field] == 1 for r in rows)
    fn = sum(r["truth"] == 1 and r[field] == 0 for r in rows)
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "accuracy": (tp + tn) / len(rows),
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None}


def _mcnemar_exact(baseline_only: int, candidate_only: int) -> float:
    n = baseline_only + candidate_only
    if n == 0:
        return 1.0
    cutoff = min(baseline_only, candidate_only)
    term = tail = 1
    for k in range(1, cutoff + 1):
        term = term * (n - k + 1) // k
        tail += term
    return min(1.0, (2 * tail) / (1 << n))


def compare(manifest_bytes: bytes, pinned_manifest_sha256: str, world: bytes,
            baseline_capture: bytes, candidate_capture: bytes,
            baseline_export: bytes, baseline_interval: bytes,
            candidate_export: bytes, candidate_interval: bytes,
            baseline_assignment: bytes, candidate_assignment: bytes,
            baseline_keys: tuple[bytes, bytes, bytes],
            candidate_keys: tuple[bytes, bytes, bytes]) -> dict:
    """Score the exact same independently labelled opportunities in both arms.

    Inputs must come from separate instrumented runs. A signed policy-name
    assignment does not independently attest the algorithm actually executed.
    """
    manifest = verify_manifest(manifest_bytes, world, pinned_manifest_sha256)
    if any(not isinstance(k, bytes) or len(k) < 16 for k in (*baseline_keys, *candidate_keys)):
        raise ValueError("six distinct receipt secrets of >=16 bytes are required")
    if len(set((*baseline_keys, *candidate_keys))) != 6:
        raise ValueError("baseline/candidate receipt secrets must be independent")
    baseline = verify_pair(
        world, baseline_capture, manifest_bytes, pinned_manifest_sha256,
        baseline_export, baseline_interval, baseline_keys[0], baseline_keys[1])
    candidate = verify_pair(
        world, candidate_capture, manifest_bytes, pinned_manifest_sha256,
        candidate_export, candidate_interval, candidate_keys[0], candidate_keys[1])
    verify_assignment(baseline_assignment, manifest, pinned_manifest_sha256,
                      baseline_capture, "baseline", baseline_keys[2])
    verify_assignment(candidate_assignment, manifest, pinned_manifest_sha256,
                      candidate_capture, "candidate", candidate_keys[2])

    b_alerts, c_alerts = _predictions(baseline_capture), _predictions(candidate_capture)
    universe = rows_from_bytes(world, WORLD_COLUMNS)
    records = [{"incident_id": row["incident_id"],
                "cluster_id": manifest["independent_cluster_id"],
                "truth": int(row["ground_truth"]),
                "baseline": int(row["incident_id"] in b_alerts),
                "candidate": int(row["incident_id"] in c_alerts)} for row in universe]
    b = _metrics(records, "baseline")
    c = _metrics(records, "candidate")
    if (b["tp"], b["fp"], b["tn"], b["fn"]) != (
            baseline["tp"], baseline["fp"], baseline["tn"], baseline["fn"]):
        raise ValueError("baseline receipt and paired confusion matrix disagree")
    if (c["tp"], c["fp"], c["tn"], c["fn"]) != (
            candidate["tp"], candidate["fp"], candidate["tn"], candidate["fn"]):
        raise ValueError("candidate receipt and paired confusion matrix disagree")

    candidate_only = sum(r["candidate"] == r["truth"] != r["baseline"] for r in records)
    baseline_only = sum(r["baseline"] == r["truth"] != r["candidate"] for r in records)
    return {
        "publication_ready": False,
        "status": "paired_capture_integrity_not_impact_evidence",
        "experiment_id": manifest["experiment_id"],
        "scenario_id": manifest["scenario_id"], "seed": manifest["seed"],
        "split": manifest["split"],
        "claimed_cluster_id": manifest["independent_cluster_id"],
        "baseline_policy_claim": manifest["baseline_name"],
        "candidate_policy_claim": manifest["candidate_name"],
        "world_incidents": len(records),
        "baseline": b, "candidate": c,
        "accuracy_difference_pp": 100 * (c["accuracy"] - b["accuracy"]),
        "baseline_only_correct": baseline_only,
        "candidate_only_correct": candidate_only,
        "mcnemar_exact_two_sided_p_descriptive": _mcnemar_exact(baseline_only, candidate_only),
        "source_sha256": {
            "manifest": digest(manifest_bytes), "world": digest(world),
            "baseline_capture": digest(baseline_capture),
            "candidate_capture": digest(candidate_capture),
            "baseline_export_receipt": digest(baseline_export),
            "candidate_export_receipt": digest(candidate_export),
            "baseline_interval_receipt": digest(baseline_interval),
            "candidate_interval_receipt": digest(candidate_interval),
            "baseline_assignment_receipt": digest(baseline_assignment),
            "candidate_assignment_receipt": digest(candidate_assignment),
        },
        "incident_rows": records,
        "limitations": [
            "Hub receipt and assignment HMACs attest export and method *claims*, not instrumented policy execution.",
            "Both capture_complete flags are operator self-assertions, not independent proof of network or sensor uptime.",
            "World labels require independent provenance; a cluster_id string is not independent replication.",
            "McNemar descriptive p-value assumes independent incident units; repeated/correlated incidents violate that assumption.",
            "Only one scenario/seed is evaluated here; effect size and p-value are not publication-ready experimental evidence.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Signed paired V2X incident comparison; no publication claims")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--pinned-manifest-sha256", required=True)
    parser.add_argument("--world", type=Path, required=True)
    parser.add_argument("--baseline-capture", type=Path, required=True)
    parser.add_argument("--candidate-capture", type=Path, required=True)
    for arm in ARMS:
        for item in ("export-receipt", "interval-receipt", "assignment-receipt",
                     "export-key", "interval-key", "assignment-key"):
            parser.add_argument("--" + arm + "-" + item, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    a = parser.parse_args()
    def read(arm, name):
        return getattr(a, arm + "_" + name.replace("-", "_")).read_bytes()
    report = compare(
        a.manifest.read_bytes(), a.pinned_manifest_sha256, a.world.read_bytes(),
        a.baseline_capture.read_bytes(), a.candidate_capture.read_bytes(),
        read("baseline", "export-receipt"), read("baseline", "interval-receipt"),
        read("candidate", "export-receipt"), read("candidate", "interval-receipt"),
        read("baseline", "assignment-receipt"), read("candidate", "assignment-receipt"),
        tuple(read("baseline", name) for name in ("export-key", "interval-key", "assignment-key")),
        tuple(read("candidate", name) for name in ("export-key", "interval-key", "assignment-key")),
    )
    payload = canonical(report)
    a.output.write_bytes(payload)
    print(json.dumps({"output_sha256": digest(payload), "publication_ready": False,
                      "incident_count": report["world_incidents"]}))


if __name__ == "__main__":
    main()
