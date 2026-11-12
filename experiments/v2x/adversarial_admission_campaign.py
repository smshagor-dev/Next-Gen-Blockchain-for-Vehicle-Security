"""Deterministic V2X incident-admission adversarial *software* campaigns.

Exercise the actual EvidenceAdmissionGate against identical constructed traces
for authentication-only, quorum-2, quorum-3 and wide-radius policies.

WARNING: identities, delivery, ground truth, losses and session_verified are
scripted *synthetic inputs*, NOT independently authenticated packet captures,
real-world incidents, research replicates or physical actuation evidence.
The campaign is an executable threat-model regression, NOT publishable results.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from v2x_evidence_admission import EvidenceAdmissionGate
from experiments.v2x.consistent_subset_admission import ConsistentSubsetAdmissionGate

ORIGIN = datetime(2026, 1, 1, tzinfo=timezone.utc)
METHODS = ("authenticated_only", "quorum_two", "quorum_three", "wide_radius", "consistent_subset")
METRE_LATITUDE = 1.0 / 111_320.0
MAX_SEEDS = 100
SCENARIOS: tuple[tuple[str, bool, tuple[tuple[float, str, str, float, float, bool, bool], ...]], ...] = (
    # offset seconds, source, sensor-digest salt, north displacement in metres,
    # observation age seconds, transport session verified, command-smuggling
    ("true_corroborated", True, (
        (0.0, "HONEST_A", "honest_a", 0, 0, True, False),
        (0.25, "HONEST_B", "honest_b", 15, 0, True, False),
    )),
    ("true_partitioned", True, (
        (0.0, "HONEST_A", "honest_a", 0, 0, True, False),
    )),
    ("true_three_reports", True, (
        (0.0, "HONEST_A", "honest_a", 0, 0, True, False),
        (0.18, "HONEST_B", "honest_b", 12, 0, True, False),
        (0.4, "HONEST_C", "honest_c", 20, 0, True, False),
    )),
    ("true_displaced_observers", True, (
        (0.0, "HONEST_A", "honest_a", 0, 0, True, False),
        (0.2, "HONEST_B", "honest_b", 250, 0, True, False),
    )),
    ("true_temporal_gap", True, (
        (0.0, "HONEST_A", "honest_a", 0, 0, True, False),
        (7.0, "HONEST_B", "honest_b", 15, 0, True, False),
    )),
    # Compromised enrolled sender speaks first under the same event id,
    # poisoning first-observation position and blocking later honest reports.
    ("true_incident_id_preemption", True, (
        (0.0, "MALICIOUS_A", "preempt", 750, 0, True, False),
        (0.25, "HONEST_A", "honest_a", 0, 0, True, False),
        (0.5, "HONEST_B", "honest_b", 10, 0, True, False),
    )),
    ("false_single_enrolled", False, (
        (0.0, "MALICIOUS_A", "malice_a", 0, 0, True, False),
    )),
    ("false_colluding_enrolled", False, (
        (0.0, "MALICIOUS_A", "malice_a", 0, 0, True, False),
        (0.25, "MALICIOUS_B", "malice_b", 5, 0, True, False),
    )),
    ("false_repeated_identity", False, (
        (0.0, "MALICIOUS_A", "first", 0, 0, True, False),
        (0.25, "MALICIOUS_A", "second", 0, 0, True, False),
    )),
    ("false_copied_digest", False, (
        (0.0, "MALICIOUS_A", "copied", 0, 0, True, False),
        (0.25, "MALICIOUS_B", "copied", 5, 0, True, False),
    )),
    ("false_geo_conflict", False, (
        (0.0, "MALICIOUS_A", "one", 0, 0, True, False),
        (0.25, "MALICIOUS_B", "two", 250, 0, True, False),
    )),
    ("false_unverified_transport", False, (
        (0.0, "UNVERIFIED", "forged", 0, 0, False, False),
    )),
    ("false_signed_action_field", False, (
        (0.0, "MALICIOUS_A", "action", 0, 0, True, True),
        (0.25, "MALICIOUS_B", "action_b", 5, 0, True, False),
    )),
)


@dataclass(frozen=True)
class SyntheticReport:
    trial_seed: int
    scenario: str
    true_incident: bool
    sender_id: str
    received_ms: int
    session_verified_claim: bool
    payload: dict[str, Any]


def make_trace(seed: int) -> list[SyntheticReport]:
    """Construct incidents with fixed truth and deterministic small timing jitter."""
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("trial seed must be nonnegative integer")
    rng = random.Random(seed)
    rows: list[SyntheticReport] = []
    for number, (name, truth, reports) in enumerate(SCENARIOS):
        anchor_ms = number * 30_000
        incident_id = f"sim-{seed}-{name}"
        for offset, sender, salt, north_metres, observed_age, verified, action in reports:
            event_ms = anchor_ms + round(offset * 1000) + rng.randrange(0, 9)
            observed_at = ORIGIN + timedelta(milliseconds=event_ms)
            observed_at -= timedelta(seconds=observed_age)
            digest = hashlib.sha256(f"{seed}:{incident_id}:{salt}".encode()).hexdigest()
            payload: dict[str, Any] = {
                "evidence": {
                    "incident_id": incident_id,
                    "event_class": "ROAD_HAZARD",
                    "observed_at": observed_at.isoformat(),
                    "lat": 51.5 + north_metres * METRE_LATITUDE,
                    "lon": -0.1,
                    "sensor_sha256": digest,
                }
            }
            if action:
                payload["remote_brake_pressure"] = 100
            rows.append(SyntheticReport(
                trial_seed=seed,
                scenario=name, true_incident=truth,
                sender_id=sender, received_ms=event_ms,
                session_verified_claim=verified, payload=payload,
            ))
    rows.sort(key=lambda report: (report.received_ms, report.scenario, report.sender_id))
    return rows


def evaluate_trace(rows: list[SyntheticReport]) -> dict[str, Any]:
    if not rows or len({r.trial_seed for r in rows}) != 1:
        raise ValueError("exactly one scripted seed is required")
    clock = {"ms": rows[0].received_ms}
    wall_clock = lambda: ORIGIN + timedelta(milliseconds=clock["ms"])
    gates = {
        "quorum_two": EvidenceAdmissionGate(
            quorum=2, clock=lambda: clock["ms"] / 1000, utc_clock=wall_clock,
        ),
        "quorum_three": EvidenceAdmissionGate(
            quorum=3, clock=lambda: clock["ms"] / 1000, utc_clock=wall_clock,
        ),
        "wide_radius": EvidenceAdmissionGate(
            quorum=2, max_distance_m=10_000,
            clock=lambda: clock["ms"] / 1000, utc_clock=wall_clock,
        ),
        "consistent_subset": ConsistentSubsetAdmissionGate(
            quorum=2, max_reports=16, max_distance_m=100,
            clock=lambda: clock["ms"] / 1000, utc_clock=wall_clock,
        ),
    }
    known: dict[str, bool] = {}
    first_receipt: dict[str, int] = {}
    relayed: dict[str, dict[str, int]] = {method: {} for method in METHODS}
    vote_sources: dict[str, dict[str, list[str]]] = {method: {} for method in METHODS}
    accepted_sources: dict[str, dict[str, list[str]]] = {method: {} for method in METHODS}
    decisions: list[dict[str, Any]] = []
    for report in rows:
        if report.received_ms < clock["ms"]:
            raise ValueError("trace times must be nondecreasing")
        clock["ms"] = report.received_ms
        prior = known.setdefault(report.scenario, report.true_incident)
        if prior is not report.true_incident:
            raise ValueError("conflicting synthetic incident truth")
        first_receipt.setdefault(report.scenario, report.received_ms)
        summary: dict[str, Any] = {
            "seed": report.trial_seed, "scenario": report.scenario,
            "ground_truth_scripted": report.true_incident,
            "time_ms": report.received_ms,
            "sender_enrolled_claim": report.sender_id,
            "transport_verified_scripted": report.session_verified_claim,
            "source_is_synthetic": True,
        }
        if report.session_verified_claim:
            if report.scenario not in relayed["authenticated_only"]:
                relayed["authenticated_only"][report.scenario] = report.received_ms
                accepted_sources["authenticated_only"][report.scenario] = [report.sender_id]
            summary["authenticated_only"] = "relayed"
        else:
            summary["authenticated_only"] = "unverified_not_forwarded"
        for name, gate in gates.items():
            if not report.session_verified_claim:
                summary[name] = "unverified_not_forwarded"
                continue
            decision = gate.evaluate(
                authenticated_sender_id=report.sender_id, payload=report.payload,
            )
            summary[name] = f"{decision.status}:{decision.reason}"
            if decision.status in ("pending", "accepted"):
                vote_sources[name].setdefault(report.scenario, []).append(report.sender_id)
            if decision.relayed:
                relayed[name].setdefault(report.scenario, report.received_ms)
                if name == "consistent_subset":
                    # Candidate records the actual selected mutual-consistency
                    # clique, not everyone who reported a poisoned incident.
                    selected = gate.accepted_sources_for(
                        report.payload["evidence"]["incident_id"]
                    )
                    accepted_sources[name][report.scenario] = list(selected)
                else:
                    accepted_sources[name][report.scenario] = list(
                        vote_sources[name][report.scenario]
                    )
        decisions.append(summary)
    metrics: dict[str, Any] = {}
    for name in METHODS:
        tp = fp = tn = fn = 0
        latencies = []
        for scenario, truth in known.items():
            detected = scenario in relayed[name]
            if truth and detected:
                tp += 1
                latencies.append(relayed[name][scenario] - first_receipt[scenario])
            elif truth:
                fn += 1
            elif detected:
                fp += 1
            else:
                tn += 1
        metrics[name] = {
            "tp_incidents": tp, "fp_incidents": fp, "tn_incidents": tn, "fn_incidents": fn,
            "false_acceptance_rate": fp / (fp + tn) if fp + tn else None,
            "legitimate_delivery_rate": tp / (tp + fn) if tp + fn else None,
            "time_to_forward_ms": latencies,
            "mean_time_to_forward_ms": sum(latencies) / len(latencies) if latencies else None,
            "malicious_assisted_admitted_incidents": sum(
                any(source.startswith("MALICIOUS_") for source in sources)
                for sources in accepted_sources[name].values()
            ),
            "policy_counters": gates[name].snapshot() if name in gates else None,
        }
    evidence = {method: sorted(receipts) for method, receipts in relayed.items()}
    return {
        "seed": rows[0].trial_seed, "methods": metrics,
        "accepted_by_scenario": evidence,
        "accepted_voter_roles": {
            method: {
                scenario: ["malicious" if node.startswith("MALICIOUS_") else "nonmalicious_scripted"
                           for node in sources]
                for scenario, sources in cases.items()
            }
            for method, cases in accepted_sources.items()
        },
        "decisions": decisions,
    }


def run_campaign(output_dir: Path, *, seeds: Sequence[int] = tuple(range(12))) -> dict[str, Any]:
    seeds = tuple(seeds)
    if not seeds or len(seeds) > MAX_SEEDS or len(set(seeds)) != len(seeds):
        raise ValueError("supply 1..100 distinct synthetic seeds")
    if any(isinstance(s, bool) or not isinstance(s, int) or s < 0 for s in seeds):
        raise ValueError("invalid synthetic seed")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    trials = [evaluate_trace(make_trace(seed)) for seed in seeds]
    rows = [decision for trial in trials for decision in trial["decisions"]]
    traces_file = output_dir / "synthetic_adversarial_decisions.csv"
    with traces_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=[
            "seed", "scenario", "ground_truth_scripted", "time_ms",
            "sender_enrolled_claim", "transport_verified_scripted",
            "source_is_synthetic", *METHODS,
        ])
        writer.writeheader()
        writer.writerows(rows)
    report = {
        "status": "synthetic_adversarial_software_campaign",
        "publication_ready": False,
        "independent_empirical_runs": 0,
        "statistical_significance": False,
        "source_origin": "constructed_deterministic_synthetic_cases_no_real_incident_ground_truth",
        "trial_seeds": list(seeds),
        "scenario_count_per_seed": len(SCENARIOS),
        "comparison_methods": list(METHODS),
        "per_seed": [
            {"seed": trial["seed"], "methods": trial["methods"],
             "accepted_by_scenario": trial["accepted_by_scenario"],
             "accepted_voter_roles": trial["accepted_voter_roles"]}
            for trial in trials
        ],
        "limitations": [
            "The gateway is exercised as a real software policy, but packet sessions, node identity, truth and network delivery are scripted, not independently verified.",
            "Many seeds change only bounded deterministic time jitter, not independent network simulations or independent participant samples.",
            "No actual VeReMi incident truth, CAN traffic, physical local emergency control or in-vehicle hardware is evaluated.",
            "Colluding enrolled identities can satisfy quorum; single honest reports and partitioned hazards are suppressed.",
            "A compromised source can preempt an honest incident ID, poisoning the first reference location and suppressing later honest reports.",
            "A true incident accepted by an untrusted corroborator must be separately marked as malicious-assisted; incident TP counts alone overstate trustworthy corroboration.",
            "Policy off in the production V2X hub remains the default; this campaign never activates vehicle actuation.",
            "The consistent-subset alternative is research-only and not wired into the hub; it may still be defeated by colluding malicious sources or bounded-pool flooding.",
            "The alternative's selection is combinatorially bounded at 16 candidate reports and quorum <=4 and requires independent runtime/availability validation.",
            "No statistical inference, publishable attack effect, vehicle safety claim or novel cryptographic primitive is established.",
        ],
    }
    report_file = output_dir / "synthetic_adversarial_campaign.json"
    report_file.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    manifest = {
        "source": "synthetic_software_fixtures",
        "publication_ready": False,
        "results_sha256": hashlib.sha256(report_file.read_bytes()).hexdigest(),
        "decisions_sha256": hashlib.sha256(traces_file.read_bytes()).hexdigest(),
    }
    (output_dir / "synthetic_campaign_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run synthetic adversarial V2X admission policy checks.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seed-count", type=int, default=12)
    args = parser.parse_args(argv)
    if not 1 <= args.seed_count <= MAX_SEEDS:
        parser.error("seed-count must be between 1 and 100")
    result = run_campaign(Path(args.output_dir), seeds=tuple(range(args.seed_count)))
    print(json.dumps({
        "status": result["status"], "seeds": len(result["trial_seeds"]),
        "scenario_count_per_seed": result["scenario_count_per_seed"],
        "publication_ready": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
