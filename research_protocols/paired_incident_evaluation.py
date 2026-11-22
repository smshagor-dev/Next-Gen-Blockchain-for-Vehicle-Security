"""Incident-cluster paired bootstrap for externally labelled V2X admission decisions.

CSV columns: incident_id, truth, baseline, candidate (binary 0/1).
Never treat repeated packets within one incident as independent samples.
"""
import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

def load(path):
    groups = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not {"incident_id", "truth", "baseline", "candidate"} <= set(reader.fieldnames or []):
            raise ValueError("required columns missing")
        for row in reader:
            incident = row["incident_id"].strip()
            values = [row[k].strip() for k in ("truth", "baseline", "candidate")]
            if not incident or any(v not in ("0", "1") for v in values):
                raise ValueError("invalid incident or nonbinary decision")
            groups[incident].append(tuple(map(int, values)))
    if not groups:
        raise ValueError("empty dataset")
    if any(len({row[0] for row in rows}) != 1 for rows in groups.values()):
        raise ValueError("conflicting truth within incident")
    return groups

def rates(rows, index):
    tp = sum(r[0] == 1 and r[index] == 1 for r in rows)
    fn = sum(r[0] == 1 and r[index] == 0 for r in rows)
    fp = sum(r[0] == 0 and r[index] == 1 for r in rows)
    tn = sum(r[0] == 0 and r[index] == 0 for r in rows)
    return {"tpr": tp/(tp+fn) if tp+fn else None,
            "fpr": fp/(fp+tn) if fp+tn else None,
            "tp":tp, "fn":fn, "fp":fp, "tn":tn}

def evaluate(groups, seed=17, repetitions=2000):
    if repetitions < 100:
        raise ValueError("at least 100 bootstrap replicates required")
    ids = sorted(groups)
    rows = [r for i in ids for r in groups[i]]
    baseline, candidate = rates(rows, 1), rates(rows, 2)
    rng = random.Random(seed)
    samples = {"tpr":[], "fpr":[]}
    for _ in range(repetitions):
        sampled = [r for _ in ids for r in groups[rng.choice(ids)]]
        a, b = rates(sampled, 1), rates(sampled, 2)
        for metric in samples:
            if a[metric] is not None and b[metric] is not None:
                samples[metric].append(b[metric] - a[metric])
    differences = {}
    for metric, values in samples.items():
        values.sort()
        a, b = baseline[metric], candidate[metric]
        differences[metric] = {
            "difference": None if a is None or b is None else b-a,
            "ci95": [values[int(.025*(len(values)-1))],
                     values[int(.975*(len(values)-1))]] if values else None,
            "valid_replicates": len(values)}
    return {"incidents":len(ids), "rows":len(rows), "baseline":baseline,
            "candidate":candidate, "paired_cluster_bootstrap":differences,
            "seed":seed, "repetitions":repetitions,
            "limitation":"Descriptive uncertainty, not proof of significance or causal superiority."}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_csv", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--repetitions", type=int, default=2000)
    args = parser.parse_args()
    result = evaluate(load(args.input_csv), args.seed, args.repetitions)
    result["input_sha256"] = hashlib.sha256(args.input_csv.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")

if __name__ == "__main__":
    main()
