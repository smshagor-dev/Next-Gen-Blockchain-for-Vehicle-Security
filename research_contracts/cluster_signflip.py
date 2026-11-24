"""Pre-specified paired cluster sign-flip analysis; not an effectiveness result.

Assumes independent, sign-exchangeable clusters under a sharp null. Do not
treat observational data or frames within a recording as independent trials.
"""
import itertools
import math
import random
from collections import defaultdict


def paired_cluster_test(rows, *, seed=2026, permutations=9999, exact_limit=16):
    """Rows: (cluster_id, incident_id, baseline_score, candidate_score)."""
    if not isinstance(permutations, int) or permutations < 1:
        raise ValueError("permutations must be positive")
    if not isinstance(exact_limit, int) or not 1 <= exact_limit <= 20:
        raise ValueError("invalid exact_limit")
    clusters = defaultdict(list)
    seen = set()
    for cluster, incident, baseline, candidate in rows:
        if not isinstance(cluster, str) or not cluster.strip() or not isinstance(incident, str) or not incident.strip():
            raise ValueError("nonempty IDs required")
        if incident in seen:
            raise ValueError("duplicate incident ID")
        seen.add(incident)
        values = (float(baseline), float(candidate))
        if any(not math.isfinite(v) or not 0 <= v <= 1 for v in values):
            raise ValueError("scores must be finite in [0, 1]")
        clusters[cluster].append(values[1] - values[0])
    if len(clusters) < 2:
        raise ValueError("at least two independent clusters required")
    effects = [math.fsum(clusters[k]) / len(clusters[k]) for k in sorted(clusters)]
    observed = math.fsum(effects) / len(effects)
    threshold = abs(math.fsum(effects))
    if len(effects) <= exact_limit:
        extreme = sum(
            abs(math.fsum(s * e for s, e in zip(signs, effects))) + 1e-12 >= threshold
            for signs in itertools.product((-1, 1), repeat=len(effects))
        )
        total = 2 ** len(effects)
        p_value = extreme / total
        method = "exact"
    else:
        rng = random.Random(seed)
        extreme = sum(
            abs(math.fsum(e if rng.getrandbits(1) else -e for e in effects)) + 1e-12 >= threshold
            for _ in range(permutations)
        )
        p_value = (extreme + 1) / (permutations + 1)
        total = permutations
        method = "monte_carlo"
    return {
        "clusters": len(effects),
        "incidents": len(seen),
        "cluster_equal_weight_mean_difference": observed,
        "two_sided_p_value": p_value,
        "method": method,
        "randomizations": total,
        "assumption": "independent sign-exchangeable clusters under the sharp null",
    }
