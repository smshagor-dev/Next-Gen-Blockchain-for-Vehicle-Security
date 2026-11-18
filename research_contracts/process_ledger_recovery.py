"""Independent OS-process SQLite surrogate contention experiment; never actuates hardware.

Run: python -m research_contracts.process_ledger_recovery --trials 10 --workers 4
This is a negative-control correctness probe, NOT blockchain finality or a
publication-ready effectiveness/latency benchmark.
"""
import argparse
import json
import multiprocessing as mp
import sqlite3
import tempfile
from pathlib import Path

from research_contracts.durable_event_inbox import DurableEventInbox, InboxConflict
from research_contracts.ledger_inbox_reconciliation import LedgerReconciler, LedgerIdentityConflict, ReconciliationUnavailable
from research_contracts.sigkill_ledger_recovery import SqliteAtomicLedgerSurrogate


def _worker(inbox_path, ledger_path, index, conflicting, start, ready, output):
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
        output.put((index, "setup_or_unexpected_error:" + type(exc).__name__))
    finally:
        if inbox is not None:
            inbox.close()
        if ledger is not None:
            ledger.close()


def trial(directory, workers=4, conflicting=False):
    if not 2 <= workers <= 16:
        raise ValueError("workers must be 2..16")
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
                                         conflicting, start, ready, output))
        for i in range(workers)
    ]
    observations = []
    try:
        for process in processes:
            process.start()
        # Release only after every process has opened its own DB connections.
        for _ in processes:
            ready.get(timeout=20)
        start.set()
        for _ in processes:
            observations.append(output.get(timeout=20))
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
              and count == 1 and committed == 1 and pending == 0 and digests == 1
              and all(kind in ("accepted", "conflict") for kind in categories)
              and ("conflict" in categories if conflicting else
                   all(kind == "accepted" for kind in categories)))
    return {"passed": passed, "workers": workers, "conflicting": conflicting,
            "outcomes": sorted(observations), "exitcodes": exitcodes,
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
