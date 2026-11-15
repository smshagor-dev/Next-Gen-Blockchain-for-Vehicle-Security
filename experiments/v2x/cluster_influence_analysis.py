"""Leave-one-independent-cluster-out sensitivity for paired incident accuracy.

Descriptive analysis only. Each cluster is an independently sampled scenario,
recording or vehicle group established before scoring. No p-value is inferred.
"""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

FIELDS = ["incident_id", "cluster_id", "truth", "baseline", "candidate"]


def analyze(path):
    with Path(path).open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != FIELDS:
            raise ValueError("exact incident/cluster paired schema required")
        rows = list(reader)
    if not rows or any(None in r or any(v is None for v in r.values()) for r in rows):
        raise ValueError("empty or ragged CSV")
    clusters = defaultdict(list)
    seen = set()
    for row in rows:
        incident, cluster = row["incident_id"], row["cluster_id"]
        if not incident or not incident.strip() or not cluster or not cluster.strip():
            raise ValueError("blank incident or cluster")
        if incident in seen:
            raise ValueError("duplicate incident ID")
        seen.add(incident)
        if any(row[k] not in ("0", "1") for k in ("truth", "baseline", "candidate")):
            raise ValueError("nonbinary label or prediction")
        delta = int(row["candidate"] == row["truth"]) - int(row["baseline"] == row["truth"])
        clusters[cluster].append(delta)
    if len(clusters) < 3:
        raise ValueError("at least three independent clusters required for leave-one-out sensitivity")
    total_n = len(rows)
    total_delta = sum(sum(v) for v in clusters.values())
    estimate = 100 * total_delta / total_n
    omissions = []
    for cluster in sorted(clusters):
        values = clusters[cluster]
        remaining = total_n - len(values)
        if remaining <= 0:
            raise ValueError("no observations remain")
        effect = 100 * (total_delta - sum(values)) / remaining
        omissions.append({"omitted_cluster": cluster, "remaining_incidents": remaining,
                          "estimate_pp": effect, "change_from_full_pp": effect - estimate})
    effects = [v["estimate_pp"] for v in omissions]
    # A zero effect is a null crossing, not a reversal of direction.
    strict_reversal = any(estimate * value < 0 for value in effects)
    reaches_null = any(value == 0 for value in effects)
    return {"incidents": total_n, "independent_clusters": len(clusters),
            "full_estimate_pp": estimate, "leave_one_cluster_out": omissions,
            "minimum_loo_pp": min(effects), "maximum_loo_pp": max(effects),
            "sign_reversal_under_omission": strict_reversal,
            "reaches_null_under_omission": reaches_null,
            "publication_ready": False,
            "limitations": "Descriptive sensitivity, not a confidence interval or significance test. Cluster independence, source authenticity, and preregistered grouping require external verification."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv")
    args = parser.parse_args()
    print(json.dumps(analyze(args.csv), indent=2))
