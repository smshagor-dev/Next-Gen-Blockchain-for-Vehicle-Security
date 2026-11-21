"""Cluster-by-seed uncertainty for paired synthetic V2X admission outcomes.

Incident rows within one simulation seed are not independent replicates.
No field-effectiveness or statistical-significance claim is implied.
"""
import argparse
import csv
import random
from collections import defaultdict


def summarize(rows, baseline, candidate, *, metric="false_admission", draws=2000, seed=31415):
    if baseline == candidate or metric not in ("false_admission", "missed_hazard") or type(draws) is not int or draws < 1:
        raise ValueError("invalid comparison")
    paired = defaultdict(dict)
    for row in rows:
        policy = row["policy"]
        if policy not in (baseline, candidate):
            continue
        key = (int(row["seed"]), int(row["incident"]))
        if policy in paired[key]:
            raise ValueError("duplicate incident-policy row")
        value = int(row[metric])
        truth = int(row["truth_hazard"])
        if value not in (0, 1) or truth not in (0, 1):
            raise ValueError("nonbinary ground truth or outcome")
        paired[key][policy] = (value, truth, row["observed_bits"])
    if not paired or any(set(pair) != {baseline, candidate} for pair in paired.values()):
        raise ValueError("unpaired incident")
    by_seed = defaultdict(list)
    for (replicate, _), pair in paired.items():
        a, b = pair[baseline], pair[candidate]
        if a[1:] != b[1:]:
            raise ValueError("unmatched ground truth or observations")
        if (metric == "false_admission" and a[1] == 0) or (metric == "missed_hazard" and a[1] == 1):
            by_seed[replicate].append((a[0], b[0]))
    if len(by_seed) < 2 or any(not pairs for pairs in by_seed.values()):
        raise ValueError("need at least two seeds with relevant incidents each")
    seeds = sorted(by_seed)
    def effect(sampled):
        pairs = [pair for replicate in sampled for pair in by_seed[replicate]]
        return sum(candidate_value - baseline_value for baseline_value, candidate_value in pairs) / len(pairs)
    rng = random.Random(seed)
    bootstrap = sorted(effect([rng.choice(seeds) for _ in seeds]) for _ in range(draws))
    return dict(metric=metric, baseline=baseline, candidate=candidate,
                seeds=len(seeds), incidents=sum(map(len, by_seed.values())),
                risk_difference=effect(seeds),
                ci95_low=bootstrap[int(.025 * (draws - 1))],
                ci95_high=bootstrap[int(.975 * (draws - 1))],
                method="seed-cluster-bootstrap-percentile", bootstrap_draws=draws)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("input_csv")
    p.add_argument("--baseline", default="authentication_only")
    p.add_argument("--candidate", default="dissent_tolerant_groups")
    p.add_argument("--draws", type=int, default=2000)
    p.add_argument("--seed", type=int, default=31415)
    args = p.parse_args()
    with open(args.input_csv, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for metric in ("false_admission", "missed_hazard"):
        print(summarize(rows, args.baseline, args.candidate, metric=metric,
                        draws=args.draws, seed=args.seed))


if __name__ == "__main__":
    main()
