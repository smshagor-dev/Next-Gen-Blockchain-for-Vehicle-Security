"""Non-actuating OS-process exit-before-readiness negative control.

This experiment tests whether a parent detects a worker that terminates
without publishing a readiness message. It does not test ledger finality.
Run: python -m research_contracts.process_readiness_fault
"""
import argparse
import json
import multiprocessing as mp
import os
import time
from queue import Empty


def _worker(mode, ready, release):
    if mode == "exit":
        os._exit(23)
    if mode == "silent":
        release.wait(10)
        return
    ready.put("ready")
    release.wait(10)


def probe(mode="exit", timeout=2.0):
    if mode not in ("exit", "silent", "normal"):
        raise ValueError("unknown mode")
    if not 0.1 <= timeout <= 10:
        raise ValueError("timeout must be between 0.1 and 10 seconds")
    ctx = mp.get_context("spawn")
    ready, release = ctx.Queue(), ctx.Event()
    child = ctx.Process(target=_worker, args=(mode, ready, release))
    child.start()
    signal = None
    reason = "timeout"
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            try:
                signal = ready.get(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
                reason = "ready"
                break
            except Empty:
                if not child.is_alive():
                    reason = "exited_before_ready"
                    break
    finally:
        release.set()
        child.join(timeout=1)
        if child.is_alive():
            child.kill()
            child.join(timeout=1)
        ready.close()
        ready.join_thread()
    return {"mode": mode, "reason": reason, "signal": signal,
            "exitcode": child.exitcode,
            "detected": reason == ("ready" if mode == "normal" else
                                    "exited_before_ready" if mode == "exit" else "timeout")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()
    rows = [probe(mode, args.timeout) for mode in ("normal", "exit", "silent")]
    print(json.dumps({"environment": "spawned-process-negative-control",
                      "not_ledger_or_hardware_evidence": True,
                      "observations": rows}, sort_keys=True))
    if not all(row["detected"] for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
