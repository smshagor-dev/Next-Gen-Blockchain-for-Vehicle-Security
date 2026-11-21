"""Negative-control experiment: volatile replay state is lost after receiver restart.

Uses the actual loopback campaign Receiver/envelope, not production hardware.
No actuator, no network exposure beyond 127.0.0.1. A replay accepted after
restart is an EXPECTED VULNERABILITY, not a successful security outcome.
"""
import argparse
import csv
import json
import socket
import struct
import threading
from pathlib import Path

from research_contracts.loopback_attack_campaign import Receiver, envelope


def deliver(receiver, packet):
    """Exercise the receiver through a real local socket pair, not direct state edits."""
    left, right = socket.socketpair()
    result = {}
    try:
        def worker():
            with right:
                result["outcome"] = receiver.handle(right)
        thread = threading.Thread(target=worker)
        thread.start()
        left.sendall(packet)
        left.shutdown(socket.SHUT_WR)
        thread.join(timeout=3)
        if thread.is_alive():
            raise RuntimeError("receiver failed to terminate within deadline")
        return result["outcome"]
    finally:
        left.close()


def run(seed=17, trials=100, output=None):
    if type(seed) is not int or seed < 0 or type(trials) is not int or trials < 1:
        raise ValueError("seed must be nonnegative integer; trials positive integer")
    # Fresh sender per trial, so no cross-trial state affects outcomes.
    rows = []
    for i in range(trials):
        packet = envelope(f"restart-{seed}-{i}", 1, 0)
        live = Receiver()
        first = deliver(live, packet)
        replay_before_restart = deliver(live, packet)
        restarted = Receiver()  # simulates volatile-state loss, NOT a real process crash
        replay_after_restart = deliver(restarted, packet)
        expected = ("accept", "replay", "accept")
        observed = (first, replay_before_restart, replay_after_restart)
        if observed != expected:
            raise AssertionError(f"trial {i}: {observed} != {expected}")
        rows.append(dict(seed=seed, trial=i, initial=first,
                         same_process_replay=replay_before_restart,
                         after_state_loss=replay_after_restart,
                         replay_accepted_after_restart=True))
    if output is not None:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--output")
    args = parser.parse_args()
    rows = run(args.seed, args.trials, args.output)
    print(json.dumps(dict(trials=len(rows), volatile_replay_bypass=sum(
        row["replay_accepted_after_restart"] for row in rows),
        finding="EXPECTED NEGATIVE CONTROL: restart loses replay state",
        evidence_scope="synthetic localhost socketpair; not production or real crash")))
