"""Non-actuating paired fault experiment for replay admission ordering.

This is a deterministic protocol MODEL, not a V2X dataset experiment, real
network benchmark, or proof of a deployed trusted anchor. Every protocol sees
identical pre-generated incident faults for each seed. No physical commands.
"""
from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

PROTOCOLS = ("sqlite_only", "reserve_first", "local_first")


def trial(protocol: str, *, local_failure: bool, anchor_failure: bool,
          restore_snapshot: bool) -> dict[str, int]:
    """One valid first admission, retry, then historical rollback/replay.

    A failed operation has no actuation. Local-first deliberately models a
    non-atomic two-store sequence: local success before anchor failure cannot
    be considered an authorized admission.
    """
    if protocol not in PROTOCOLS:
        raise ValueError("unknown protocol")
    local = set()
    anchor = set()
    nonce = "incident-nonce"
    accepted = 0
    retry_accepted = 0
    replay_accepted = 0
    rejected_valid = 0

    def admit(fail_local: bool, fail_anchor: bool) -> bool:
        if protocol == "sqlite_only":
            if fail_local or nonce in local:
                return False
            local.add(nonce)
            return True
        if protocol == "reserve_first":
            if fail_anchor or nonce in anchor:
                return False
            anchor.add(nonce)
            if fail_local or nonce in local:
                return False
            local.add(nonce)
            return True
        # Local-first does not authorize until both stores commit.
        if fail_local or nonce in local:
            return False
        local.add(nonce)
        if fail_anchor or nonce in anchor:
            return False
        anchor.add(nonce)
        return True

    first = admit(local_failure, anchor_failure)
    accepted += int(first)
    if not first:
        retry = admit(False, False)
        retry_accepted = int(retry)
        rejected_valid = int(not retry)
    if restore_snapshot:
        local.clear()  # attacker restores valid pre-admission SQLite snapshot
        # A replay only exists when the original attempt was accepted.
        if first:
            replay_accepted = int(admit(False, False))
    return dict(first_accepted=accepted, retry_accepted=retry_accepted,
                valid_retry_rejected=rejected_valid,
                rollback_replay_accepted=replay_accepted)


def experiment(seeds: int, incidents: int, local_failure_rate: float,
               anchor_failure_rate: float, rollback_rate: float):
    if seeds < 1 or incidents < 1:
        raise ValueError("seeds and incidents must be positive")
    if any(not 0 <= x <= 1 for x in
           (local_failure_rate, anchor_failure_rate, rollback_rate)):
        raise ValueError("rates must lie in [0,1]")
    for seed in range(seeds):
        rng = random.Random(seed)
        faults = [(rng.random() < local_failure_rate,
                   rng.random() < anchor_failure_rate,
                   rng.random() < rollback_rate)
                  for _ in range(incidents)]
        for protocol in PROTOCOLS:
            totals = dict(first_accepted=0, retry_accepted=0,
                          valid_retry_rejected=0, rollback_replay_accepted=0)
            for lf, af, rb in faults:
                result = trial(protocol, local_failure=lf,
                               anchor_failure=af, restore_snapshot=rb)
                for k, v in result.items():
                    totals[k] += v
            yield dict(seed=seed, protocol=protocol, incidents=incidents,
                       **totals)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--incidents", type=int, default=1000)
    parser.add_argument("--local-failure-rate", type=float, default=0.05)
    parser.add_argument("--anchor-failure-rate", type=float, default=0.05)
    parser.add_argument("--rollback-rate", type=float, default=0.2)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = list(experiment(args.seeds, args.incidents,
                           args.local_failure_rate, args.anchor_failure_rate,
                           args.rollback_rate))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} protocol-seed rows to {args.output}")


if __name__ == "__main__":
    main()
