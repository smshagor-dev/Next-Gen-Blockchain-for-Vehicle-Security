"""Paired incident-level uncertainty, never packet-level pseudoreplication.

Input CSV columns: scenario_id,incident_id,truth,baseline,proposed.
Each row represents one independently annotated incident opportunity.
This tool reports descriptive paired effect estimates, not significance.
"""
import argparse
import csv
import hashlib
import json
import random
from pathlib import Path

COLUMNS = ("scenario_id", "incident_id", "truth", "baseline", "proposed")


def read_incidents(path):
    with open(path, newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or set(reader.fieldnames) != set(COLUMNS):
            raise ValueError("expected exactly " + ",".join(COLUMNS))
        rows, seen = [], set()
        for row in reader:
            if None in row or any(v is None for v in row.values()):
                raise ValueError("malformed CSV")
            key = (row["scenario_id"], row["incident_id"])
            if not all(key) or key in seen:
                raise ValueError("empty or duplicate incident key")
            seen.add(key)
            for field in ("truth", "baseline", "proposed"):
                if row[field] not in ("0", "1"):
                    raise ValueError("binary labels required")
            rows.append((key, *(int(row[f]) for f in ("truth", "baseline", "proposed"))))
    if not rows:
        raise ValueError("empty incident universe")
    return rows


def _balanced_accuracy(rows, index):
    positives = [r for r in rows if r[1] == 1]
    negatives = [r for r in rows if r[1] == 0]
    if not positives or not negatives:
        return None
    return (sum(r[index] for r in positives) / len(positives)
            + sum(1 - r[index] for r in negatives) / len(negatives)) / 2


def compare(rows, *, seed=2026, replicates=2000):
    if replicates < 2:
        raise ValueError("at least two bootstrap replicates required")
    baseline = _balanced_accuracy(rows, 2)
    proposed = _balanced_accuracy(rows, 3)
    if baseline is None:
        return {"status": "insufficient_positive_or_negative_support",
                "n_incidents": len(rows), "effect": None, "ci95": None}
    # Stratify by truth to avoid zero-class bootstrap replicates.
    strata = [[r for r in rows if r[1] == label] for label in (0, 1)]
    rng = random.Random(seed)
    effects = []
    for _ in range(replicates):
        sample = [rng.choice(stratum) for stratum in strata
                  for _ in range(len(stratum))]
        effects.append(_balanced_accuracy(sample, 3) -
                       _balanced_accuracy(sample, 2))
    effects.sort()
    lo = effects[int(0.025 * (replicates - 1))]
    hi = effects[int(0.975 * (replicates - 1))]
    return {"status": "descriptive_cluster_unadjusted",
            "n_incidents": len(rows),
            "n_positive": len(strata[1]), "n_negative": len(strata[0]),
            "baseline_balanced_accuracy": baseline,
            "proposed_balanced_accuracy": proposed,
            "effect": proposed - baseline, "ci95": [lo, hi],
            "bootstrap_seed": seed, "bootstrap_replicates": replicates,
            "warning": "Incidents within one scenario may be correlated; this interval is not a confirmatory p-value or independent multi-scenario replication."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--replicates", type=int, default=2000)
    args = parser.parse_args()
    rows = read_incidents(args.csv)
    result = compare(rows, seed=args.seed, replicates=args.replicates)
    result["source_sha256"] = hashlib.sha256(args.csv.read_bytes()).hexdigest()
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
