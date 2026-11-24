"""Incident-grouped paired evaluation; never treat frames as independent incidents.

Input CSV columns: incident_id, split, label, baseline_score, proposed_score.
Scores must be finite in [0,1]; higher means more suspicious. Each incident
has one label and one split; evaluate only held-out 'test' incidents.
This is an analysis protocol, not a detector or a publishable dataset.
"""
import argparse
import csv
import json
import math
import random
from collections import defaultdict


def load_incidents(path):
    groups = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"incident_id", "split", "label", "baseline_score", "proposed_score"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("missing required columns")
        for row in reader:
            key = row["incident_id"].strip()
            if not key:
                raise ValueError("empty incident ID")
            if row["split"] not in {"train", "validation", "test"}:
                raise ValueError("invalid split")
            if row["label"] not in {"0", "1"}:
                raise ValueError("invalid label")
            scores = tuple(float(row[k]) for k in ("baseline_score", "proposed_score"))
            if not all(math.isfinite(s) and 0 <= s <= 1 for s in scores):
                raise ValueError("invalid score")
            groups[key].append((row["split"], int(row["label"]), *scores))
    incidents = []
    for key, observations in groups.items():
        if len({(x[0], x[1]) for x in observations}) != 1:
            raise ValueError("incident leakage or inconsistent labels: " + key)
        split, label = observations[0][:2]
        # Max aggregation represents incident-level detection, not frame-level N.
        incidents.append((key, split, label, max(x[2] for x in observations),
                          max(x[3] for x in observations)))
    return sorted(incidents)


def balanced_accuracy(records, score_index, threshold):
    pos = [x for x in records if x[2] == 1]
    neg = [x for x in records if x[2] == 0]
    if not pos or not neg:
        raise ValueError("both incident classes required")
    return (sum(x[score_index] >= threshold for x in pos) / len(pos)
            + sum(x[score_index] < threshold for x in neg) / len(neg)) / 2


def evaluate(incidents, threshold=0.5, seed=2026, replicates=2000):
    if not 0 <= threshold <= 1 or replicates < 100:
        raise ValueError("invalid threshold or bootstrap count")
    test = [x for x in incidents if x[1] == "test"]
    if not test:
        raise ValueError("no held-out test incidents")
    baseline = balanced_accuracy(test, 3, threshold)
    proposed = balanced_accuracy(test, 4, threshold)
    rng = random.Random(seed)
    positive = [x for x in test if x[2] == 1]
    negative = [x for x in test if x[2] == 0]
    differences = []
    for _ in range(replicates):
        sample = [rng.choice(positive) for _ in positive] + [rng.choice(negative) for _ in negative]
        differences.append(balanced_accuracy(sample, 4, threshold)
                           - balanced_accuracy(sample, 3, threshold))
    differences.sort()
    return {"unit": "incident", "test_incidents": len(test),
            "positive_incidents": len(positive), "negative_incidents": len(negative),
            "threshold": threshold, "seed": seed, "bootstrap_replicates": replicates,
            "baseline_balanced_accuracy": baseline,
            "proposed_balanced_accuracy": proposed, "paired_difference": proposed - baseline,
            "stratified_cluster_bootstrap_95_interval":
                [differences[int(0.025 * replicates)],
                 differences[min(replicates - 1, math.ceil(0.975 * replicates) - 1)]],
            "statistical_significance_claim": False,
            "limitations": "Exploratory interval; no significance inferred from sample size. "
                           "Threshold must be frozen before test evaluation; correlated "
                           "incidents across campaigns require higher-level clustering."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--replicates", type=int, default=2000)
    args = parser.parse_args()
    print(json.dumps(evaluate(load_incidents(args.csv_path), args.threshold,
                              args.seed, args.replicates), indent=2))


if __name__ == "__main__":
    main()
