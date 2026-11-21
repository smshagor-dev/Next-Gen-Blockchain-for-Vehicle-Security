"""Simulation-only paired factorial V2X admission comparison; no hardware actuation."""
import argparse
import csv
import math
import random
from pathlib import Path

POLICIES = ("auth_only", "sender_quorum", "strict_group", "dissent_tolerant")

def decide(reports):
    """reports: (sender, trust_group, hazard_vote); None indicates missing."""
    present = [r for r in reports if r[2] is not None]
    primary = bool(present[0][2]) if present else False
    sender_quorum = sum(v is True for _, _, v in present) >= 2
    groups = {}
    for _, group, vote in present:
        groups.setdefault(group, set()).add(vote)
    supporting = sum(v == {True} for v in groups.values())
    dissent = any(v != {True} for v in groups.values())
    return (primary, sender_quorum, supporting >= 2 and not dissent, supporting >= 2)

def simulate(seed, incidents, compromised_groups, honest_error, correlated_error):
    if incidents < 1 or compromised_groups not in (0, 1, 2) or not all(
        math.isfinite(x) and 0 <= x <= 1 for x in (honest_error, correlated_error)
    ):
        raise ValueError("invalid experiment parameters")
    rng = random.Random(seed)
    rows = []
    for incident in range(incidents):
        truth = bool(rng.getrandbits(1))
        shared_fault = rng.random() < correlated_error
        reports = []
        for group in range(3):
            for sender in range(2):
                if group < compromised_groups:
                    vote = not truth
                else:
                    vote = not truth if shared_fault or rng.random() < honest_error else truth
                reports.append((f"g{group}s{sender}", f"g{group}", vote))
        rng.shuffle(reports)
        for policy, admitted in zip(POLICIES, decide(reports)):
            rows.append(dict(seed=seed, incident=incident, compromised_groups=compromised_groups,
                             honest_error=honest_error, correlated_error=correlated_error,
                             truth=int(truth), policy=policy, admitted=int(admitted),
                             false_admission=int(admitted and not truth),
                             missed_hazard=int(not admitted and truth)))
    return rows

def run(seeds, incidents, levels, honest_error, correlated_error):
    if not seeds or len(seeds) != len(set(seeds)) or not levels or len(levels) != len(set(levels)):
        raise ValueError("seed and compromise levels must be nonempty and unique")
    return [row for level in levels for seed in seeds
            for row in simulate(seed, incidents, level, honest_error, correlated_error)]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", default="17,23,41,59,71")
    p.add_argument("--incidents", type=int, default=1000)
    p.add_argument("--compromised-groups", default="0,1,2")
    p.add_argument("--honest-error", type=float, default=.05)
    p.add_argument("--correlated-error", type=float, default=.05)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    rows = run([int(x) for x in a.seeds.split(",")], a.incidents,
               [int(x) for x in a.compromised_groups.split(",")],
               a.honest_error, a.correlated_error)
    path = Path(a.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"simulation_only=True rows={len(rows)}")

if __name__ == "__main__":
    main()
