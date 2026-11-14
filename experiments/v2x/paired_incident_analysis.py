"""Paired incident-level comparison; requires externally sourced independent labels.

CSV: incident_id,truth,baseline,candidate; predictions and labels must be 0/1.
One row per independent incident, identical rows for both methods.
"""
import argparse
import csv
import json
import math
from pathlib import Path


def analyze(path):
    with Path(path).open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ["incident_id", "truth", "baseline", "candidate"]:
            raise ValueError("expected exactly incident_id,truth,baseline,candidate columns")
        rows = list(reader)
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError("ragged incident table")
    if not rows:
        raise ValueError("empty incident table")
    ids = set()
    values = []
    for row in rows:
        key = row["incident_id"].strip()
        if not key or key in ids:
            raise ValueError("missing or duplicate incident_id")
        ids.add(key)
        vals = []
        for name in ("truth", "baseline", "candidate"):
            v = row[name].strip()
            if v not in ("0", "1"):
                raise ValueError(f"{key}: {name} must be binary")
            vals.append(int(v))
        values.append(vals)
    baseline_only = sum(b == y and c != y for y, b, c in values)
    candidate_only = sum(c == y and b != y for y, b, c in values)
    n = baseline_only + candidate_only
    if n:
        # Exact integer tail avoids floating overflow for large incident cohorts.
        # Sum the shorter binomial tail using an integer recurrence.
        cutoff = min(baseline_only, candidate_only)
        term = 1
        tail = 1
        for k in range(1, cutoff + 1):
            term = term * (n - k + 1) // k
            tail += term
        p = min(1.0, (2 * tail) / (1 << n))
    else:
        p = 1.0

    def metrics(index):
        tp = sum(y == 1 and row[index] == 1 for row in values for y in [row[0]])
        fp = sum(y == 0 and row[index] == 1 for row in values for y in [row[0]])
        fn = sum(y == 1 and row[index] == 0 for row in values for y in [row[0]])
        tn = sum(y == 0 and row[index] == 0 for row in values for y in [row[0]])
        return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
                "accuracy": (tp + tn) / len(values),
                "recall": tp / (tp + fn) if tp + fn else None,
                "false_positive_rate": fp / (fp + tn) if fp + tn else None}

    return {"incidents": len(values), "baseline": metrics(1),
            "candidate": metrics(2), "candidate_only_correct": candidate_only,
            "baseline_only_correct": baseline_only,
            "mcnemar_exact_two_sided_p": p,
            "limitations": "Independent incident units and external labels required; p-value alone does not establish scientific significance, causality, effect size, or dataset authenticity."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv")
    args = parser.parse_args()
    print(json.dumps(analyze(args.csv), indent=2))
