"""Incident-level paired replay-anchor model analysis; simulation only."""
import argparse
import csv
import math
import random
from pathlib import Path
from research_contracts.anchor_failure_tradeoff import PROTOCOLS, trial

def incident_rows(seeds, incidents, local_rate, anchor_rate, rollback_rate):
    if seeds < 1 or incidents < 1:
        raise ValueError("seeds and incidents must be positive")
    if not all(math.isfinite(x) and 0 <= x <= 1 for x in (local_rate, anchor_rate, rollback_rate)):
        raise ValueError("rates must be finite probabilities")
    for seed in range(seeds):
        rng = random.Random(seed)
        for incident in range(incidents):
            lf, af, rb = (rng.random() < local_rate, rng.random() < anchor_rate,
                          rng.random() < rollback_rate)
            for protocol in PROTOCOLS:
                yield dict(seed=seed, incident=incident, protocol=protocol,
                           local_failure=int(lf), anchor_failure=int(af),
                           snapshot_restored=int(rb),
                           **trial(protocol, local_failure=lf, anchor_failure=af,
                                   restore_snapshot=rb))

def paired_comparison(rows, protocol_a, protocol_b, outcome):
    """Paired risk difference; no independence or significance claim."""
    if protocol_a == protocol_b or protocol_a not in PROTOCOLS or protocol_b not in PROTOCOLS:
        raise ValueError("choose different known protocols")
    pairs = {}
    for row in rows:
        if row["protocol"] not in (protocol_a, protocol_b):
            continue
        key = (int(row["seed"]), int(row["incident"]))
        pair = pairs.setdefault(key, {})
        if row["protocol"] in pair:
            raise ValueError("duplicate paired observation")
        if outcome not in row or row[outcome] not in (0, 1):
            raise ValueError("binary outcome required")
        pair[row["protocol"]] = row[outcome]
    if not pairs or any(len(pair) != 2 for pair in pairs.values()):
        raise ValueError("missing paired observation")
    a_only = sum(p[protocol_a] == 1 and p[protocol_b] == 0 for p in pairs.values())
    b_only = sum(p[protocol_a] == 0 and p[protocol_b] == 1 for p in pairs.values())
    return dict(protocol_a=protocol_a, protocol_b=protocol_b, outcome=outcome,
                pairs=len(pairs), a_only=a_only, b_only=b_only,
                paired_risk_difference=(a_only - b_only) / len(pairs),
                inference_warning="Seed-cluster dependence; descriptive synthetic contrast only")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", type=int, default=30)
    p.add_argument("--incidents", type=int, default=1000)
    p.add_argument("--local-failure-rate", type=float, default=.05)
    p.add_argument("--anchor-failure-rate", type=float, default=.05)
    p.add_argument("--rollback-rate", type=float, default=.2)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    rows = list(incident_rows(a.seeds, a.incidents, a.local_failure_rate,
                              a.anchor_failure_rate, a.rollback_rate))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    for outcome in ("rollback_replay_accepted", "valid_retry_rejected"):
        print(paired_comparison(rows, "sqlite_only", "reserve_first", outcome))

if __name__ == "__main__":
    main()
