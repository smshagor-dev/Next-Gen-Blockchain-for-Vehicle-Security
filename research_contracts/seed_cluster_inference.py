"""Seed-cluster paired bootstrap for simulated incident contrasts.

Resample independent seed clusters, never individual incidents. Percentile
intervals are descriptive Monte Carlo uncertainty, not significance proofs.
"""
import math
import random
from collections import defaultdict


def cluster_paired_interval(rows, protocol_a, protocol_b, outcome,
                            *, repetitions=2000, bootstrap_seed=2026,
                            confidence=0.95):
    if protocol_a == protocol_b or not protocol_a or not protocol_b:
        raise ValueError('distinct protocols required')
    if not isinstance(repetitions, int) or repetitions < 100:
        raise ValueError('at least 100 bootstrap replicates required')
    if not math.isfinite(confidence) or not 0 < confidence < 1:
        raise ValueError('invalid confidence')
    pairs = defaultdict(dict)
    for row in rows:
        if row['protocol'] not in (protocol_a, protocol_b):
            continue
        key = (int(row['seed']), int(row['incident']))
        if row['protocol'] in pairs[key]:
            raise ValueError('duplicate paired observation')
        value = row.get(outcome)
        if value not in (0, 1) or isinstance(value, str):
            raise ValueError('binary numeric outcome required')
        pairs[key][row['protocol']] = value
    if not pairs or any(set(pair) != {protocol_a, protocol_b} for pair in pairs.values()):
        raise ValueError('incomplete matched observations')
    clusters = defaultdict(list)
    for (seed, _), pair in pairs.items():
        clusters[seed].append(pair[protocol_a] - pair[protocol_b])
    seeds = sorted(clusters)
    if len(seeds) < 2:
        raise ValueError('at least two independent seed clusters required')
    sums = [sum(clusters[s]) for s in seeds]
    counts = [len(clusters[s]) for s in seeds]
    estimate = sum(sums) / sum(counts)
    rng = random.Random(bootstrap_seed)
    draws = []
    for _ in range(repetitions):
        selected = [rng.randrange(len(seeds)) for _ in seeds]
        draws.append(sum(sums[i] for i in selected) / sum(counts[i] for i in selected))
    draws.sort()
    alpha = (1 - confidence) / 2
    lower = draws[max(0, math.ceil(alpha * repetitions) - 1)]
    upper = draws[min(repetitions - 1, math.ceil((1 - alpha) * repetitions) - 1)]
    return {'protocol_a': protocol_a, 'protocol_b': protocol_b,
            'outcome': outcome, 'seed_clusters': len(seeds),
            'paired_incidents': sum(counts), 'risk_difference': estimate,
            'ci_lower': lower, 'ci_upper': upper, 'confidence': confidence,
            'bootstrap_repetitions': repetitions,
            'bootstrap_seed': bootstrap_seed,
            'warning': 'Synthetic seed-cluster percentile bootstrap; no empirical vehicle claim or automatic significance inference'}
