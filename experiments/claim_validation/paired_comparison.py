"""Exploratory paired replay over actual-component trial traces.

Truth uses separately exported component outcomes, not gate output. This is
not external adjudication: the two channels share the trusted local process.
Evidence faults are synthetic replay interventions, not field attack rates.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from collections import Counter
from dataclasses import replace
from pathlib import Path

from experiments.claim_validation.claim_gate import evaluate_claim, DEFAULT_MAX_AGE_NS
from experiments.claim_validation.runtime_evidence import Observation, canonical

DOMAINS = {
    "consensus": ("recorded_quorum_acceptance", "consensus", 96),
    "identity": ("enrolled_session", "identity", 96),
    "pqc": ("mlkem512_session", "handshake", 48),
}
FAULTS = ("clean", "missing", "stale", "future", "wrong_scope", "wrong_kind",
          "malformed", "metadata_disagreement")
METHODS = ("posture_proxy", "declared_capability_proxy", "observed_gate",
           "without_scope_freshness")
STATUSES = {"ELIGIBLE", "NOT_SUPPORTED", "WITHHELD"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_rows(domain, directory):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if manifest["executed_sha"] != revision:
        raise ValueError("trace does not match current checkout")
    for name, expected in manifest["artifact_sha256"].items():
        if Path(name).name != name or digest(directory / name) != expected:
            raise ValueError("artifact integrity mismatch")
    if "traces.jsonl" not in manifest["artifact_sha256"]:
        raise ValueError("trace not covered by manifest")
    rows = [json.loads(line) for line in (directory / "traces.jsonl").read_text(encoding="utf-8").splitlines()]
    if len(rows) != DOMAINS[domain][2] or len({row["expected_scope"] for row in rows}) != len(rows):
        raise ValueError("missing or duplicate trial scopes")
    return rows, revision


def decode_observation(row):
    body = dict(row["runtime_evidence"])
    received = body.pop("sha256")
    if hashlib.sha256(canonical(body)).hexdigest() != received:
        raise ValueError("observation digest mismatch")
    if body["schema"] != "runtime-observation/1" or body["trust_boundary"] != "local_observer_same_process":
        raise ValueError("unexpected observation format")
    if body["scope"] != row["expected_scope"]:
        raise ValueError("original evidence scope mismatch")
    return Observation(body["kind"], body["scope"], body["monotonic_ns"],
                       tuple(sorted(body["facts"].items())))


def reference_and_metadata(domain, row):
    # Independent of gate decision, but not independently trusted.
    if domain == "consensus":
        return (row["final_status"] == "ACCEPTED", row["posture_after"],
                row["declared_membership"] is True
                and row["declared_signature_required"] is True
                and row["declared_quorum_basis"] == "configured_validator_set")
    if domain == "identity":
        return (row["authenticated_ack"] is True and row["bound_identity"] is True
                and not row["unlisted_identity_accepted"], row["posture_with_observed_alerts"],
                row["sybil_resistance_metadata"] is True)
    if domain == "pqc":
        return (row["matched_session"] is True and row["server_mode"] == "PQC_KEM"
                and row["client_mode"] == "PQC_KEM" and row["negotiated_kem"] == "ML-KEM-512",
                row["operational_posture"], row["declared_key_establishment"] == "ML-KEM/Kyber - post-quantum")
    raise ValueError("unknown domain")


def paired_row(domain, row, fault):
    claim, kind, _ = DOMAINS[domain]
    truth, posture, declared = reference_and_metadata(domain, row)
    obs = decode_observation(row)
    scope = row["expected_scope"]
    # Replay clock: offsets deliberately imposed relative to observation time.
    now = obs.monotonic_ns
    if fault == "missing":
        obs = None
    elif fault == "stale":
        now += DEFAULT_MAX_AGE_NS + 1
    elif fault == "future":
        now -= 1
    elif fault == "wrong_scope":
        obs = replace(obs, scope="0"*32 if scope != "0"*32 else "1"*32)
    elif fault == "wrong_kind":
        obs = replace(obs, kind="identity" if kind != "identity" else "handshake")
    elif fault == "malformed":
        obs = replace(obs, facts=obs.facts[:-1])
    elif fault == "metadata_disagreement":
        declared = not declared
    elif fault != "clean":
        raise ValueError("unknown fault")
    result = evaluate_claim(claim, posture, obs, expected_scope=scope, now_ns=now)
    # Ablation intentionally bypasses only scope and age checks, not kind/schema.
    # It is an offline comparator, never a production path.
    ablated = evaluate_claim(claim, posture, obs,
                             expected_scope=obs.scope if obs is not None else scope,
                             now_ns=obs.monotonic_ns if obs is not None else now)
    return {
        "domain": domain, "trial_scope": scope, "fault": fault,
        "reference_supported": truth, "posture": posture, "declared_capability": declared,
        "posture_proxy": "ELIGIBLE" if posture == "STRONG" else "WITHHELD",
        "declared_capability_proxy": "ELIGIBLE" if posture == "STRONG" and declared else "WITHHELD",
        "observed_gate": result.eligibility, "gate_reason": result.reason,
        "without_scope_freshness": ablated.eligibility,
    }


def summarize(rows):
    report = []
    for fault in FAULTS:
        group = [row for row in rows if row["fault"] == fault]
        if not group:
            continue
        for method in METHODS:
            c = Counter((row["reference_supported"], row[method]) for row in group)
            positive = sum(n for (truth, _), n in c.items() if truth)
            negative = len(group) - positive
            supported = c[True, "ELIGIBLE"]
            unsupported = c[False, "ELIGIBLE"]
            withheld = c[True, "WITHHELD"] + c[False, "WITHHELD"]
            report.append({"fault": fault, "method": method, "n": len(group),
                           "reference_positive": positive, "reference_negative": negative,
                           "supported_eligible": supported, "unsupported_eligible": unsupported,
                           "positive_withheld": c[True, "WITHHELD"],
                           "positive_not_supported": c[True, "NOT_SUPPORTED"],
                           "negative_withheld": c[False, "WITHHELD"],
                           "negative_not_supported": c[False, "NOT_SUPPORTED"],
                           "withheld": withheld,
                           "eligibility_coverage": (supported + unsupported) / len(group),
                           "unsupported_eligibility_rate": unsupported / negative if negative else None,
                           "positive_eligibility_rate": supported / positive if positive else None})
    return report


def run(domain, source, out):
    rows, revision = load_rows(domain, source)
    paired = [paired_row(domain, row, fault) for row in rows for fault in FAULTS]
    out.mkdir(parents=True, exist_ok=True)
    csv_path = out / "paired_decisions.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(paired[0]))
        writer.writeheader()
        writer.writerows(paired)
    result = {"domain": domain, "executed_sha": revision, "source_trace_sha256": digest(source / "traces.jsonl"),
              "source_manifest_sha256": digest(source / "manifest.json"),
              "comparison_source_sha256": digest(Path(__file__)),
              "base_trials": len(rows), "paired_fault_rows": len(paired),
              "methods": list(METHODS), "summary": summarize(paired),
              "paired_csv_sha256": digest(csv_path), "statistical_inference": False,
              "reference_scope": "same-process component outcome, not external adjudication"}
    (out / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"domain": domain, "base_trials": len(rows), "paired_fault_rows": len(paired),
                      "clean": [item for item in result["summary"] if item["fault"] == "clean"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", choices=DOMAINS, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.domain, args.source, args.out)
