"""Pre-registered, reproducible *synthetic* incident-world V2X policy experiment.

This is a software stochastic experiment, NOT external independent incident
ground truth, authenticated physical capture, HIL, or publishable safety proof.
World labels are created separately from delivery traces, avoiding the
received-packets-only denominator error. Transport authentication is an
assumption at the tested policy boundary; its actual MAC path is not exercised.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Sequence

from v2x_evidence_admission import EvidenceAdmissionGate
from experiments.v2x.consistent_subset_admission import ConsistentSubsetAdmissionGate

TIME = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
SCENARIOS = (
    ("true_clean", 1),
    ("true_first_writer", 1),
    ("true_partition", 1),
    ("true_zero_capture", 1),
    ("false_single", 0),
    ("false_collusion", 0),
    ("false_zero_capture", 0),
)
POLICIES = ("authenticated_only", "anchor_quorum2", "subset_quorum2")
PROTOCOL_VERSION = "synthetic-world-v1"

def _digest(*parts: object) -> str:
    return hashlib.sha256(":".join(map(str, parts)).encode("utf-8")).hexdigest()

def make_opportunity(seed: int, scenario: str, ordinal: int):
    """World oracle is defined independently of received/missing packets."""
    rng = random.Random(f"world:{seed}:{scenario}:{ordinal}")
    label = dict(SCENARIOS)[scenario]
    return {
        "seed": seed, "scenario": scenario, "ordinal": ordinal,
        "incident_id": f"s{seed}-{scenario}-{ordinal}",
        "world_hazard": label, "world_lat": 51.5 + rng.uniform(-0.05, 0.05),
        "world_lon": -0.1 + rng.uniform(-0.05, 0.05),
        "world_time": TIME.isoformat(),
        "world_source": "seeded synthetic world oracle; no external validation",
    }

def make_deliveries(world: dict):
    """Packet generation is separate: no ground-truth label is passed to gates."""
    seed, scenario, ordinal = world["seed"], world["scenario"], world["ordinal"]
    rng = random.Random(f"network:{seed}:{scenario}:{ordinal}")
    incident_id = world["incident_id"]
    lat, lon = world["world_lat"], world["world_lon"]
    deliveries: list[dict] = []

    def add(sender: str, kind: str, arrival: float):
        # The malicious location is deliberately incompatible with actual world state.
        if kind == "malicious":
            obs_lat, obs_lon = lat + 0.02, lon + 0.02
        else:
            obs_lat = lat + rng.uniform(-0.00005, 0.00005)
            obs_lon = lon + rng.uniform(-0.00005, 0.00005)
        deliveries.append({
            "incident_id": incident_id, "seed": seed, "scenario": scenario,
            "sender": sender, "source_role": kind, "arrival_sim_sec": round(arrival, 7),
            "event_class": "ROAD_HAZARD", "observed_at": TIME.isoformat(),
            "lat": obs_lat, "lon": obs_lon,
            "sensor_sha256": _digest(incident_id, sender, kind),
            "session_mac_validated": "ASSUMED_NOT_EXECUTED",
        })

    if scenario == "true_clean":
        for i in range(3):
            if rng.random() >= 0.12:
                add(f"honest_{i}", "honest", rng.uniform(0.0, 2.0))
    elif scenario == "true_first_writer":
        add("compromised_0", "malicious", -1.0)
        for i in range(3):
            if rng.random() >= 0.12:
                add(f"honest_{i}", "honest", rng.uniform(0.0, 2.0))
    elif scenario == "true_partition":
        # A disconnected or partitioned true incident has 0 or 1 received report.
        if rng.random() >= 0.5:
            add("honest_0", "honest", rng.uniform(0.0, 2.0))
    elif scenario == "true_zero_capture":
        pass
    elif scenario == "false_single":
        add("compromised_0", "malicious", rng.uniform(0.0, 2.0))
    elif scenario == "false_collusion":
        # Enrolled colluders fabricate mutually consistent independent digests.
        add("compromised_0", "malicious", rng.uniform(0.0, 0.5))
        add("compromised_1", "malicious", rng.uniform(0.5, 1.5))
    elif scenario == "false_zero_capture":
        pass
    else:
        raise ValueError("Unrecognized scenario")
    deliveries.sort(key=lambda r: (r["arrival_sim_sec"], r["sender"]))
    return deliveries

def _payload(report: dict):
    return {"evidence": {key: report[key] for key in (
        "incident_id", "event_class", "observed_at", "lat", "lon", "sensor_sha256"
    )}}

def _accepted_point(policy: str, reports: list[dict]):
    """All policies see identical ordered reports; no relay can actuate hardware."""
    if policy == "authenticated_only":
        return reports[0] if reports else None
    clock = lambda: TIME
    if policy == "anchor_quorum2":
        gate = EvidenceAdmissionGate(quorum=2, utc_clock=clock)
    elif policy == "subset_quorum2":
        gate = ConsistentSubsetAdmissionGate(quorum=2, utc_clock=clock)
    else:
        raise ValueError("Unknown policy")
    for report in reports:
        decision = gate.evaluate(
            authenticated_sender_id=report["sender"], payload=_payload(report)
        )
        if decision.relayed:
            return report
    return None

def _within_world(report: dict, world: dict) -> bool:
    # Geodesic distance is not approximated as planar latitude degrees.
    from v2x_evidence_admission import _haversine_m
    return _haversine_m(
        report["lat"], report["lon"], world["world_lat"], world["world_lon"]
    ) <= 100.0

def trial(seed: int, each: int):
    worlds, traces, results = [], [], []
    for scenario, truth in SCENARIOS:
        for ordinal in range(each):
            world = make_opportunity(seed, scenario, ordinal)
            assert world["world_hazard"] == truth
            reports = make_deliveries(world)
            worlds.append(world)
            traces.extend(reports)
            for policy in POLICIES:
                accepted = _accepted_point(policy, reports)
                correctly_located = bool(
                    accepted is not None and truth == 1 and _within_world(accepted, world)
                )
                event = {
                    "seed": seed, "incident_id": world["incident_id"],
                    "scenario": scenario, "policy": policy, "world_hazard": truth,
                    "captured_reports": len(reports), "relayed": bool(accepted),
                    "correctly_located_hazard": correctly_located,
                    "mislocated_relay": bool(accepted and truth == 1 and not correctly_located),
                    "relay_from_compromised": bool(
                        accepted and accepted["source_role"] == "malicious"
                    ),
                    # True hazard with wrong-location forwarded alert remains FN.
                    "outcome": (
                        "TP" if correctly_located else
                        "FN" if truth == 1 else
                        "FP" if accepted else "TN"
                    ),
                }
                results.append(event)
    return worlds, traces, results

def summarize(results: list[dict], seeds: int):
    summary = {
        "status": "EXPLORATORY_SYNTHETIC_ONLY",
        "publication_ready": False,
        "physical_hardware_validated": False,
        "independent_external_incident_labels": False,
        "transport_mac_verified_in_this_runner": False,
        "seed_count": seeds,
        "method": "predefined stochastic world oracle and dropped/delayed synthetic reports",
        "by_policy": {},
    }
    for policy in POLICIES:
        rows = [r for r in results if r["policy"] == policy]
        counts = Counter(row["outcome"] for row in rows)
        cases = {}
        for scenario, truth in SCENARIOS:
            subset = [r for r in rows if r["scenario"] == scenario]
            cases[scenario] = {
                "incidents": len(subset),
                "tp": sum(r["outcome"] == "TP" for r in subset),
                "fp": sum(r["outcome"] == "FP" for r in subset),
                "fn": sum(r["outcome"] == "FN" for r in subset),
                "tn": sum(r["outcome"] == "TN" for r in subset),
                "mislocated_relays": sum(r["mislocated_relay"] for r in subset),
                "compromised_origin_relays": sum(r["relay_from_compromised"] for r in subset),
                "truth": truth,
            }
        summary["by_policy"][policy] = {
            "incidents": len(rows), "TP": counts["TP"], "FP": counts["FP"],
            "FN": counts["FN"], "TN": counts["TN"],
            "by_scenario": cases,
        }
    # Paired seed-level differences, exploratory only. Never infer independence
    # from individual opportunities within the same simulator seed.
    anchor, subset = [], []
    for seed in range(seeds):
        for policy, values in (("anchor_quorum2", anchor), ("subset_quorum2", subset)):
            r = [x for x in results if x["seed"] == seed and x["policy"] == policy
                 and x["scenario"] == "true_first_writer"]
            values.append(sum(x["correctly_located_hazard"] for x in r) / len(r))
    deltas = [s - a for a, s in zip(anchor, subset)]
    boot = random.Random(34041)
    means = []
    for _ in range(1500):
        pick = [deltas[boot.randrange(seeds)] for _ in range(seeds)]
        means.append(mean(pick))
    means.sort()
    summary["exploratory_paired_first_writer"] = {
        "subset_minus_anchor_correct_hazard_relay_rate": mean(deltas),
        "bootstrap_95_percent_interval": [means[37], means[1462]],
        "unit": "independent RNG seeds under one synthetic world generator",
        "confirmatory_p_value": None,
        "novelty_established": False,
    }
    return summary

def _write_csv(path: Path, rows: list[dict]):
    if not rows:
        raise ValueError("No records")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)

def run(output_dir: Path, seeds: int = 64, each: int = 16):
    if not (2 <= seeds <= 500 and 1 <= each <= 200):
        raise ValueError("seeds must be 2..500 and each 1..200")
    output_dir.mkdir(parents=True, exist_ok=True)
    worlds, traces, results = [], [], []
    for seed in range(seeds):
        w, t, r = trial(seed, each)
        worlds.extend(w); traces.extend(t); results.extend(r)
    files = {
        "world.csv": worlds, "deliveries.csv": traces, "decisions.csv": results
    }
    for name, rows in files.items():
        _write_csv(output_dir / name, rows)
    summary = summarize(results, seeds)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    base = Path(__file__).resolve().parents[2]
    source_paths = (
        Path(__file__).resolve(), base / "v2x_evidence_admission.py",
        base / "experiments/v2x/consistent_subset_admission.py",
    )
    hashes = {
        name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest()
        for name in (*files, "summary.json")
    }
    manifest = {
        "protocol": PROTOCOL_VERSION, "seed_count": seeds,
        "opportunities_per_scenario_per_seed": each,
        "source_sha256": {
            str(p.relative_to(base)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source_paths
        },
        "output_sha256": hashes,
        "limitations": [
            "Labels are generated by this stochastic simulator, not an external world oracle.",
            "Session authentication is assumed; no live hub packet MAC verified.",
            "Delivery model is simplified and not a radio/traffic simulator.",
            "No vehicle, ECU, CAN, GPIO, or physical emergency stop operated.",
            "The per-opportunity gate is reset; multi-incident pool stress is not evaluated.",
            "Confidence interval is exploratory for this one model, not field generalization.",
        ],
        "publication_ready": False,
        "physical_hardware_validated": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seeds", type=int, default=64)
    parser.add_argument("--per-scenario", type=int, default=16)
    args = parser.parse_args(argv)
    outcome = run(Path(args.output_dir), seeds=args.seeds, each=args.per_scenario)
    print(json.dumps({
        "status": outcome["status"], "seed_count": outcome["seed_count"],
        "publication_ready": outcome["publication_ready"],
        "world_incidents_per_policy": sum(
            row["incidents"] for row in outcome["by_policy"]["anchor_quorum2"]["by_scenario"].values()
        ),
    }, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
