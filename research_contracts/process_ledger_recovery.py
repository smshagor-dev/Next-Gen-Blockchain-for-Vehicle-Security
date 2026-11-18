"""Independent OS-process SQLite surrogate contention experiment; never actuates hardware.

Run: python -m research_contracts.process_ledger_recovery --trials 10 --workers 4
This is a negative-control correctness probe, NOT blockchain finality or a
publication-ready effectiveness/latency benchmark.
"""
import argparse
import json
import multiprocessing as mp
import sqlite3
import os
import time
import tempfile
from queue import Empty
from pathlib import Path

from research_contracts.durable_event_inbox import DurableEventInbox, InboxConflict
from research_contracts.ledger_inbox_reconciliation import LedgerReconciler, LedgerIdentityConflict, ReconciliationUnavailable
from research_contracts.sigkill_ledger_recovery import SqliteAtomicLedgerSurrogate


def _worker(inbox_path, ledger_path, index, conflicting, start, ready, output, exit_before_ready=None):
    if index == exit_before_ready:
        os._exit(23)  # controlled failure before opening a database
    inbox = ledger = None
    try:
        inbox = DurableEventInbox(inbox_path)
        ledger = SqliteAtomicLedgerSurrogate(ledger_path)
        ready.put(index)
        if not start.wait(timeout=15):
            output.put((index, "timeout"))
            return
        payload = {"speed": 4 if conflicting and index % 2 else 3}
        try:
            LedgerReconciler(inbox, ledger).reconcile("test-pi", "nonce-001", payload)
            output.put((index, "accepted"))
        except (InboxConflict, LedgerIdentityConflict) as exc:
            output.put((index, "conflict"))
        except (sqlite3.Error, ReconciliationUnavailable) as exc:
            output.put((index, "storage_or_ledger_error"))
    except Exception as exc:
        ready.put(("setup_failed", index))
        output.put((index, "setup_or_unexpected_error:" + type(exc).__name__))
    finally:
        if inbox is not None:
            inbox.close()
        if ledger is not None:
            ledger.close()


def trial(directory, workers=4, conflicting=False, exit_before_ready=None):
    if not 2 <= workers <= 16:
        raise ValueError("workers must be 2..16")
    if exit_before_ready is not None and not 0 <= exit_before_ready < workers:
        raise ValueError("exit_before_ready must identify a worker")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    inbox_path, ledger_path = directory / "inbox.sqlite", directory / "ledger.sqlite"
    inbox = DurableEventInbox(inbox_path)
    ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    inbox.close()
    ledger.close()
    ctx = mp.get_context("spawn")
    start, ready, output = ctx.Event(), ctx.Queue(), ctx.Queue()
    processes = [
        ctx.Process(target=_worker, args=(str(inbox_path), str(ledger_path), i,
                                         conflicting, start, ready, output, exit_before_ready))
        for i in range(workers)
    ]
    observations = []
    setup_failures = []
    timed_out = False
    try:
        for process in processes:
            process.start()
        # Release only after every process has opened its own DB connections.
        # A failed child setup must not strand the parent at the readiness barrier.
        ready_indices = set()
        deadline = time.monotonic() + 20
        while len(ready_indices) + len(set(setup_failures)) < workers:
            try:
                signal = ready.get(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
                if isinstance(signal, tuple) and signal[0] == "setup_failed":
                    setup_failures.append(signal[1])
                elif isinstance(signal, int):
                    ready_indices.add(signal)
            except Empty:
                pass
            # Check every child, including those which never write to either queue.
            premature = [i for i, process in enumerate(processes)
                         if i not in ready_indices and i not in setup_failures
                         and not process.is_alive() and process.exitcode is not None]
            if premature:
                setup_failures.extend(premature)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
        # Do not release partial cohorts into storage writes after setup failure.
        if not setup_failures and not timed_out:
            start.set()
            for _ in processes:
                try:
                    observations.append(output.get(timeout=20))
                except Empty:
                    timed_out = True
                    break
    finally:
        start.set()
        for process in processes:
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
    inbox = DurableEventInbox(inbox_path)
    ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    try:
        count = ledger.count()
        pending = len(inbox.pending())
        committed = inbox.db.execute(
            "SELECT COUNT(*) FROM inbox WHERE state='COMMITTED'").fetchone()[0]
        digests = inbox.db.execute("SELECT COUNT(DISTINCT digest) FROM inbox").fetchone()[0]
    finally:
        inbox.close()
        ledger.close()
    categories = [kind for _, kind in observations]
    exitcodes = [process.exitcode for process in processes]
    passed = (len(observations) == workers and all(code == 0 for code in exitcodes)
              and not timed_out and not setup_failures
              and count == 1 and committed == 1 and pending == 0 and digests == 1
              and all(kind in ("accepted", "conflict") for kind in categories)
              and ("conflict" in categories if conflicting else
                   all(kind == "accepted" for kind in categories)))
    return {"passed": passed, "workers": workers, "conflicting": conflicting,
            "exit_before_ready": exit_before_ready,
            "outcomes": sorted(observations), "exitcodes": exitcodes,
            "setup_failures": sorted(setup_failures), "timed_out": timed_out,
            "ledger_records": count, "pending": pending,
            "committed": committed, "distinct_digests": digests}


def run(trials=10, workers=4):
    if not 1 <= trials <= 100:
        raise ValueError("trials must be 1..100")
    if not 2 <= workers <= 16:
        raise ValueError("workers must be 2..16")
    with tempfile.TemporaryDirectory() as root:
        rows = [trial(Path(root) / str(i), workers, conflicting=bool(i % 2))
                for i in range(trials)]
    return {"environment": "independent-spawned-processes-sqlite-surrogate",
            "not_blockchain_finality": True, "trials": trials,
            "all_assertions_passed": all(row["passed"] for row in rows),
            "observations": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    result = run(args.trials, args.workers)
    print(json.dumps(result, sort_keys=True))
    if not result["all_assertions_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
