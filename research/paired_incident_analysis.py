"""Paired incident-level evaluation; analysis only, not evidence generation.

Input CSV: incident_id,split,method,unsafe_accept,latency_ms
One row per (incident, method). Compare methods on identical held-out incidents.
No claim of statistical significance follows from sample count alone.
"""
import argparse
import csv
import json
import math
import random
from collections import defaultdict
from pathlib import Path


def load_pairs(path, baseline, candidate):
    rows = defaultdict(dict)
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"incident_id", "split", "method", "unsafe_accept", "latency_ms"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("missing required columns")
        for row in reader:
            if row["split"] != "test" or row["method"] not in (baseline, candidate):
                continue
            key = row["incident_id"]
            if not key:
                raise ValueError("empty incident ID")
            method = row["method"]
            if method in rows[key]:
                raise ValueError("duplicate incident/method")
            if row["unsafe_accept"] not in ("0", "1"):
                raise ValueError("unsafe_accept must be binary")
            latency = float(row["latency_ms"])
            if not math.isfinite(latency) or latency < 0:
                raise ValueError("invalid latency")
            rows[key][method] = (int(row["unsafe_accept"]), latency)
    if not rows:
        raise ValueError("no held-out test incidents")
    if any(set(v) != {baseline, candidate} for v in rows.values()):
        raise ValueError("unpaired incident; refusing biased comparison")
    return [rows[k] for k in sorted(rows)]


def paired_analysis(pairs, baseline, candidate, seed=2026, resamples=2000):
    if baseline == candidate:
        raise ValueError("methods must differ")
    if resamples < 100:
        raise ValueError("at least 100 bootstrap resamples required")
    # Negative means candidate has fewer unsafe admissions.
    differences = [p[candidate][0] - p[baseline][0] for p in pairs]
    latency_differences = [p[candidate][1] - p[baseline][1] for p in pairs]
    rng = random.Random(seed)
    n = len(pairs)
    means = []
    for _ in range(resamples):
        means.append(sum(differences[rng.randrange(n)] for _ in range(n)) / n)
    means.sort()
    def mean(xs):
        return sum(xs) / len(xs)
    # Exact two-sided paired sign test on discordant binary outcomes.
    positive = sum(d > 0 for d in differences)
    negative = sum(d < 0 for d in differences)
    discordant = positive + negative
    p_value = min(1.0, 2 * sum(math.comb(discordant, k) for k in range(min(positive, negative) + 1)) / (2 ** discordant)) if discordant else 1.0
    return {
        "analysis_unit": "paired_heldout_incident",
        "n_incidents": n,
        "baseline": baseline,
        "candidate": candidate,
        "unsafe_accept_rate_difference": mean(differences),
        "bootstrap_95pct_ci": [means[int(0.025 * resamples)], means[min(resamples - 1, int(0.975 * resamples))]],
        "paired_sign_test_p_two_sided": p_value,
        "discordant_incidents": discordant,
        "mean_latency_difference_ms": mean(latency_differences),
        "seed": seed,
        "bootstrap_resamples": resamples,
        "limitations": "Exploratory paired incident analysis. Independent incident sampling and authentic provenance must be established separately; bootstrap does not repair dataset leakage or correlated incidents."
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--resamples", type=int, default=2000)
    args = parser.parse_args()
    if args.baseline == args.candidate:
        parser.error("baseline and candidate must differ")
    pairs = load_pairs(args.csv_path, args.baseline, args.candidate)
    print(json.dumps(paired_analysis(pairs, args.baseline, args.candidate, args.seed, args.resamples), indent=2))


if __name__ == "__main__":
    main()
