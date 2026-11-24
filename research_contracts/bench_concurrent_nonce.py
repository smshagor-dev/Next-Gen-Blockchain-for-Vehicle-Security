"""Concurrent SQLite nonce admission experiments; simulated identities only.

This is a controlled component experiment, NOT an authenticated TCP or vehicle
experiment. Repetitions are correlated; do not treat attempts as independent
research samples or infer significance from their count.
"""
import argparse
import csv
import random
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hardware_nonce_store import SQLiteNonceStore, NonceStoreError


def run(seed, workers, attempts, capacity, output):
    if workers < 1 or attempts < 2 or capacity < 1:
        raise ValueError("invalid experiment dimensions")
    # A fixed, paired sequence: every even index replays the preceding
    # honest nonce; odd indices use distinct fresh nonces. Scheduling order
    # is nondeterministic, so report outcomes rather than expected rejection.
    if type(seed) is not int or seed < 0 or seed >= 2**64:
        raise ValueError("seed must be an unsigned 64-bit integer")
    if type(attempts) is not int or attempts % 2:
        raise ValueError("attempts must be even for matched nonce pairs")
    workload = [
        (i, "first_copy" if i % 2 == 0 else "second_copy",
         f"{seed:016x}{i // 2:016x}") for i in range(attempts)
    ]
    # Randomized submission order; labels are not attacker ground truth.
    random.Random(seed).shuffle(workload)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "claims.sqlite")
        store = SQLiteNonceStore(path, provision=True, max_claims=capacity)
        def attempt(entry):
            index, label, nonce = entry
            start = time.perf_counter_ns()
            try:
                accepted = store.claim("simulated-node", nonce, ttl_seconds=30)
                outcome = "accepted" if accepted else "duplicate_rejected"
            except NonceStoreError:
                outcome = "capacity_rejected"
            return {
                "seed": seed, "workers": workers, "attempt_index": index,
                "workload_label": label, "outcome": outcome,
                "latency_ns": time.perf_counter_ns() - start,
            }
        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                rows = list(pool.map(attempt, workload))
        finally:
            store.close()
    # Check matched-pair safety before writing an evidence artifact.
    accepted = {}
    pairs = {}
    for row in rows:
        key = row["attempt_index"] // 2
        pairs[key] = pairs.get(key, 0) + 1
        if row["outcome"] == "accepted":
            accepted[key] = accepted.get(key, 0) + 1
    if any(n > 1 for n in accepted.values()):
        raise AssertionError("duplicate nonce admitted under concurrency")
    if any(n != 2 for n in pairs.values()):
        raise AssertionError("incomplete matched nonce pair")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return {
        "attempts": len(rows),
        "accepted": sum(row["outcome"] == "accepted" for row in rows),
        "duplicate_rejected": sum(row["outcome"] == "duplicate_rejected" for row in rows),
        "capacity_rejected": sum(row["outcome"] == "capacity_rejected" for row in rows),
        "median_latency_ns": statistics.median(row["latency_ns"] for row in rows),
        "output": str(output),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20261117)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--attempts", type=int, default=400)
    parser.add_argument("--capacity", type=int, default=200)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(run(args.seed, args.workers, args.attempts, args.capacity, args.output))
