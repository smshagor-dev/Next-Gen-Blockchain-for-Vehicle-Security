"""Scenario-clustered descriptive paired bootstrap for incident decisions.

Rows: ((scenario_id, incident_id), truth, baseline, proposed).
Resample whole scenarios, preserving within-scenario dependence and pairing.
No confirmatory significance claims.
"""
import random
from collections import defaultdict


def _ba(rows, prediction):
    positive = [r for r in rows if r[1] == 1]
    negative = [r for r in rows if r[1] == 0]
    if not positive or not negative:
        return None
    return (sum(r[prediction] for r in positive) / len(positive) +
            sum(1 - r[prediction] for r in negative) / len(negative)) / 2


def compare_clustered(rows, *, seed=2026, replicates=2000):
    if not isinstance(replicates, int) or isinstance(replicates, bool) or replicates < 2:
        raise ValueError("replicates must be an integer >= 2")
    groups = defaultdict(list)
    seen = set()
    for row in rows:
        if len(row) != 4 or len(row[0]) != 2:
            raise ValueError("invalid incident tuple")
        key, truth, baseline, proposed = row
        if not all(isinstance(x, str) and x for x in key) or key in seen:
            raise ValueError("invalid or repeated incident key")
        if any(type(v) is not int or v not in (0, 1) for v in (truth, baseline, proposed)):
            raise ValueError("binary integer labels required")
        seen.add(key)
        groups[key[0]].append(row)
    if len(groups) < 2:
        return {"status": "insufficient_independent_scenarios", "n_scenarios": len(groups), "ci95": None}
    all_rows = [r for group in groups.values() for r in group]
    observed, base = _ba(all_rows, 3), _ba(all_rows, 2)
    if observed is None:
        return {"status": "insufficient_class_support", "n_scenarios": len(groups), "ci95": None}
    ids = sorted(groups)
    rng = random.Random(seed)
    effects, invalid = [], 0
    for _ in range(replicates):
        sample = [r for _ in ids for r in groups[rng.choice(ids)]]
        p, b = _ba(sample, 3), _ba(sample, 2)
        if p is None:
            invalid += 1
        else:
            effects.append(p - b)
    if invalid or len(effects) < 2:
        return {"status": "unstable_class_support_under_cluster_resampling",
                "n_scenarios": len(ids), "n_incidents": len(seen),
                "effect": observed - base, "ci95": None,
                "invalid_replicates": invalid, "bootstrap_replicates": replicates,
                "warning": "Cluster draws lost a class; do not silently condition on valid replicates."}
    effects.sort()
    return {"status": "descriptive_cluster_bootstrap", "n_scenarios": len(ids),
            "n_incidents": len(seen), "effect": observed - base,
            "ci95": [effects[int(.025 * (replicates - 1))], effects[int(.975 * (replicates - 1))]],
            "bootstrap_seed": seed, "bootstrap_replicates": replicates,
            "warning": "Descriptive interval only; scenarios must be independently sampled for population inference."}
