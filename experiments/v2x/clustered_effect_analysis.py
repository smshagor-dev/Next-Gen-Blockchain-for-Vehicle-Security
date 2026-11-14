"""Cluster-aware paired accuracy uncertainty. Input: incident_id,cluster_id,truth,baseline,candidate.
Clusters must be independent scenarios, not repeated frames. Synthetic tests are not evidence.
"""
import argparse
import csv
import json
import random
from collections import defaultdict
from pathlib import Path

FIELDS = ["incident_id", "cluster_id", "truth", "baseline", "candidate"]

def analyze(path, *, seed=2026, repetitions=2000, confidence=0.95):
    if repetitions < 100 or not 0 < confidence < 1:
        raise ValueError("repetitions >= 100 and 0 < confidence < 1 required")
    with Path(path).open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != FIELDS:
            raise ValueError("expected exact incident_id,cluster_id,truth,baseline,candidate columns")
        rows = list(reader)
    if not rows or any(None in r or any(v is None for v in r.values()) for r in rows):
        raise ValueError("empty or ragged CSV")
    clusters, seen = defaultdict(list), set()
    for row in rows:
        incident, cluster = row["incident_id"].strip(), row["cluster_id"].strip()
        if not incident or not cluster or incident in seen:
            raise ValueError("blank identifier or duplicate incident")
        seen.add(incident)
        for field in ("truth", "baseline", "candidate"):
            if row[field] not in ("0", "1"):
                raise ValueError(f"{incident}: invalid binary {field}")
        improvement = int(row["candidate"] == row["truth"]) - int(row["baseline"] == row["truth"])
        clusters[cluster].append(improvement)
    if len(clusters) < 2:
        raise ValueError("at least two independent clusters required")
    keys = sorted(clusters)
    rng = random.Random(seed)
    observed = sum(map(sum, clusters.values())) / len(rows)
    draws = []
    for _ in range(repetitions):
        sampled = [clusters[keys[rng.randrange(len(keys))]] for _ in keys]
        draws.append(sum(map(sum, sampled)) / sum(map(len, sampled)))
    draws.sort()
    alpha = (1 - confidence) / 2
    low = draws[int(alpha * repetitions)]
    high = draws[min(repetitions - 1, int((1 - alpha) * repetitions))]
    return {
        "incidents": len(rows), "clusters": len(keys),
        "effect": "candidate minus baseline paired accuracy (percentage points)",
        "estimate_pp": 100 * observed,
        "cluster_bootstrap_percentile_ci_pp": [100 * low, 100 * high],
        "confidence": confidence, "bootstrap_repetitions": repetitions, "seed": seed,
        "limitations": "Descriptive percentile cluster bootstrap: independent representative clusters and externally validated ground truth required. No significance or causal claim."
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--repetitions", type=int, default=2000)
    args = parser.parse_args()
    print(json.dumps(analyze(args.csv, seed=args.seed, repetitions=args.repetitions), indent=2))
