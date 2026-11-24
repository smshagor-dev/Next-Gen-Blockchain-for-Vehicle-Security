"""Finite-design paired contrasts and observer trust failure sensitivity."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from dataclasses import replace
from pathlib import Path

from experiments.claim_validation.design_reference import adjudicate
from experiments.claim_validation.paired_comparison import (
    DOMAINS, FAULTS, METHODS, decode_observation, digest, load_rows, paired_row,
)
from experiments.claim_validation.claim_gate import evaluate_claim


def scenario_result(domain, row):
    reference = adjudicate(domain, row)
    clean = paired_row(domain, row, "clean")
    return {**clean, "design_truth": reference["truth"], "design_cell": reference["cell"],
            "design_execution_agrees": reference["direct_agrees"],
            "reference_channels_agree": clean["reference_supported"] is reference["truth"]}


def sensitivity(domain, row, reference):
    """Construct a schema-consistent contrary local observation offline.

    Explicit observer trust violation, not a bypass of a deployed interface.
    Keep scope and freshness valid; do not change the original trace or oracle.
    """
    obs = decode_observation(row)
    claim = DOMAINS[domain][0]
    facts = dict(obs.facts)
    # Model loss of the trusted same-process observation boundary.
    # No injected input is sent to a running vehicle, network or service.
    if domain == "pqc":
        positive = {"completed": True, "matched_session": True, "client_mode": "PQC_KEM",
                    "server_mode": "PQC_KEM", "negotiated_kem": "ML-KEM-512"}
        negative = dict(positive, client_mode="PSK", server_mode="PSK", negotiated_kem="")
    elif domain == "identity":
        positive = {"bound": True, "authenticated_ack": True, "registry_member": True,
                    "registry_size": max(1, facts["registry_size"])}
        negative = dict(positive, registry_member=False)
    else:
        q, n = facts["quorum_threshold"], facts["validator_count"]
        positive = dict(facts, yes_votes=q, no_votes=0, status="ACCEPTED")
        negative = dict(facts, yes_votes=0, no_votes=n-q+1, status="REJECTED")
    altered = replace(obs, facts=tuple(sorted((negative if reference["truth"] else positive).items())))
    # Actual posture retained; no forced healthy state for rejected sessions.
    clean = paired_row(domain, row, "clean")
    outcome = evaluate_claim(claim, clean["posture"], altered,
                             expected_scope=row["expected_scope"], now_ns=obs.monotonic_ns)
    return {"domain": domain, "trial_scope": row["expected_scope"], "design_cell": reference["cell"],
            "design_truth": reference["truth"], "posture": clean["posture"],
            "clean_gate": clean["observed_gate"], "altered_gate": outcome.eligibility,
            "altered_reason": outcome.reason,
            "false_eligibility": not reference["truth"] and outcome.eligibility == "ELIGIBLE",
            "lost_true_eligibility": reference["truth"] and clean["observed_gate"] == "ELIGIBLE"
                                    and outcome.eligibility != "ELIGIBLE"}


def paired_contrasts(rows):
    """Equal-weight design cells; no inference from repeated deterministic trials."""
    results = []
    for fault in FAULTS:
        for comparator in METHODS:
            if comparator == "observed_gate":
                continue
            for truth in (False, True):
                selected = [x for x in rows if x["fault"] == fault and x["design_truth"] is truth]
                cells = defaultdict(list)
                for x in selected:
                    delta = int(x["observed_gate"] == "ELIGIBLE") - int(x[comparator] == "ELIGIBLE")
                    cells[x["design_cell"]].append(delta)
                cell_delta = {k: sum(v)/len(v) for k,v in sorted(cells.items())}
                results.append({"fault": fault, "comparator": comparator, "reference_positive": truth,
                                "trials": len(selected), "design_cells": len(cells),
                                "gate_minus_comparator_eligibility": sum(cell_delta.values())/len(cells) if cells else None,
                                "cell_deltas": cell_delta,
                                "range_across_design_cells": [min(cell_delta.values()), max(cell_delta.values())] if cells else None})
    return results


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run(domain, source, out):
    rows, revision = load_rows(domain, source)
    refs = [scenario_result(domain, row) for row in rows]
    mismatches = [x for x in refs if not (x["design_execution_agrees"] and x["reference_channels_agree"])]
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "reference_checks.csv", refs)
    # Never quietly discard disagreement. Preserve it before terminating.
    if mismatches:
        (out / "reference_disagreements.json").write_text(json.dumps(mismatches, indent=2), encoding="utf-8")
        raise RuntimeError("reference disagreement; inspect retained artifact before interpretation")
    paired = []
    altered = []
    for row in rows:
        ref = adjudicate(domain, row)
        for fault in FAULTS:
            paired.append({**paired_row(domain, row, fault), "design_truth": ref["truth"],
                           "design_cell": ref["cell"]})
        altered.append(sensitivity(domain, row, ref))
    write_csv(out / "paired_design_decisions.csv", paired)
    write_csv(out / "observer_sensitivity.csv", altered)
    report = {"domain": domain, "executed_sha": revision, "base_trials": len(rows),
              "design_cells": len({x["design_cell"] for x in refs}),
              "reference_disagreements": len(mismatches), "paired_rows": len(paired),
              "observer_trust_failure_rows": len(altered),
              "observer_false_eligibilities": sum(x["false_eligibility"] for x in altered),
              "observer_lost_true_eligibilities": sum(x["lost_true_eligibility"] for x in altered),
              "observer_negative_trials": sum(not x["design_truth"] for x in altered),
              "observer_positive_trials": sum(x["design_truth"] for x in altered),
              "observer_negative_strong_trials": sum(not x["design_truth"] and x["posture"] == "STRONG" for x in altered),
              "paired_contrasts": paired_contrasts(paired),
              "trace_sha256": digest(source / "traces.jsonl"),
              "reference_source_sha256": digest(Path(__file__).with_name("design_reference.py")),
              "analysis_source_sha256": digest(Path(__file__)),
              "artifact_sha256": {name: digest(out/name) for name in
                                  ("reference_checks.csv", "paired_design_decisions.csv", "observer_sensitivity.csv")},
              "statistical_inference": False,
              "reference_scope": "separate design calculation; same local test environment",
              "observer_scope": "deliberate hypothetical trust-boundary violation; not attack prevalence"}
    (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k,v in report.items() if k != "paired_contrasts"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", choices=DOMAINS, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.domain, args.source, args.out)
