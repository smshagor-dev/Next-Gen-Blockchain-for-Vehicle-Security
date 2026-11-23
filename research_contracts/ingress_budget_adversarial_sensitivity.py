"""Deterministic, non-actuating admission-budget adversarial sensitivity study.

Models *post-authentication* requests only; no MAC, socket, ledger or vehicle.
The question is whether global rate limiting protects capacity while denying
legitimate enrolled devices under coordinated malicious enrolled-node flooding.
"""
import argparse
import csv
import json
import random
from collections import defaultdict


def simulate(*, seed=0, honest=3, adversaries=3, seconds=30,
             capacity=8, honest_rate=2, adversary_rate=12, policy="global"):
    if min(honest, adversaries, seconds, capacity, honest_rate, adversary_rate) < 0:
        raise ValueError("negative parameter")
    if seconds == 0 or capacity == 0 or honest == 0:
        raise ValueError("positive seconds, capacity and honest required")
    if policy not in ("global", "per_identity", "unlimited"):
        raise ValueError("unknown policy")
    rng = random.Random(seed)
    counts = defaultdict(int)
    per_actor = defaultdict(int)
    for second in range(seconds):
        arrivals = []
        for i in range(honest):
            arrivals.extend((i, True) for _ in range(honest_rate))
        for i in range(adversaries):
            arrivals.extend((honest + i, False) for _ in range(adversary_rate))
        rng.shuffle(arrivals)
        used = 0
        actor_used = defaultdict(int)
        for actor, is_honest in arrivals:
            # Equal per-identity shares are only a model, not Sybil resistance.
            share = max(1, capacity // (honest + adversaries))
            allowed = (policy == "unlimited" or
                       (policy == "global" and used < capacity) or
                       (policy == "per_identity" and
                        actor_used[actor] < share and used < capacity))
            key = "honest" if is_honest else "adversarial"
            counts[key + "_offered"] += 1
            if allowed:
                used += 1
                actor_used[actor] += 1
                per_actor[actor] += 1
                counts[key + "_admitted"] += 1
    offered = counts["honest_offered"]
    return {
        "seed": seed, "policy": policy, "honest": honest,
        "adversaries": adversaries, "seconds": seconds,
        "capacity_per_second": capacity,
        "honest_offered": offered,
        "honest_admitted": counts["honest_admitted"],
        "adversarial_offered": counts["adversarial_offered"],
        "adversarial_admitted": counts["adversarial_admitted"],
        "honest_admission_fraction": counts["honest_admitted"] / offered
        if offered else None,
        "admitted_total": sum(per_actor.values()),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--adversaries", type=int, default=3)
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    if not 1 <= args.seeds <= 10000:
        parser.error("seeds must be between 1 and 10000")
    results = [
        simulate(seed=seed, adversaries=args.adversaries, policy=policy)
        for seed in range(args.seeds)
        for policy in ("global", "per_identity", "unlimited")
    ]
    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(results[0]))
            writer.writeheader()
            writer.writerows(results)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
