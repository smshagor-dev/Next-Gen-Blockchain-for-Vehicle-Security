"""Concurrent independent-connection recovery experiment, NON-ACTUATING.

Uses SQLite surrogate, not blockchain consensus. This is a concurrency correctness
probe, not publishable latency/effectiveness evidence.
Run: python -m research_contracts.concurrent_ledger_recovery --trials 20 --workers 4
"""
import argparse
import concurrent.futures
import json
import sqlite3
import tempfile
import threading
from pathlib import Path

from research_contracts.durable_event_inbox import DurableEventInbox, InboxConflict
from research_contracts.ledger_inbox_reconciliation import LedgerReconciler
from research_contracts.sigkill_ledger_recovery import SqliteAtomicLedgerSurrogate


def campaign_trial(directory, workers=4, conflicting=False):
    directory.mkdir(parents=True, exist_ok=True)
    inbox_path = directory / "inbox.sqlite"
    ledger_path = directory / "ledger.sqlite"
    # Initialize before releasing concurrent workers; no schema creation races.
    inbox = DurableEventInbox(inbox_path)
    ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    inbox.close()
    ledger.close()
    barrier = threading.Barrier(workers)

    def work(index):
        local_inbox = DurableEventInbox(inbox_path)
        local_ledger = SqliteAtomicLedgerSurrogate(ledger_path)
        try:
            barrier.wait(timeout=10)
            payload = {"speed": 3 if not conflicting or index % 2 == 0 else 4}
            try:
                outcome = LedgerReconciler(local_inbox, local_ledger).reconcile(
                    "test-pi", "nonce-001", payload)
                return ("accepted", outcome)
            except InboxConflict:
                return ("conflict", "inbox")
            except sqlite3.OperationalError as exc:
                return ("storage_error", type(exc).__name__)
        finally:
            local_inbox.close()
            local_ledger.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(work, range(workers)))
    check_inbox = DurableEventInbox(inbox_path)
    check_ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    try:
        records = check_ledger.count()
        pending = len(check_inbox.pending())
        committed = check_inbox.db.execute(
            "SELECT COUNT(*) FROM inbox WHERE state='COMMITTED'").fetchone()[0]
        distinct = check_inbox.db.execute(
            "SELECT COUNT(DISTINCT digest) FROM inbox").fetchone()[0]
    finally:
        check_inbox.close()
        check_ledger.close()
    accepted = sum(kind == "accepted" for kind, _ in outcomes)
    conflicts = sum(kind == "conflict" for kind, _ in outcomes)
    storage_errors = sum(kind == "storage_error" for kind, _ in outcomes)
    expected = (records == 1 and committed == 1 and pending == 0
                and distinct == 1 and storage_errors == 0
                and (accepted + conflicts == workers)
                and (conflicts >= 1 if conflicting else conflicts == 0))
    return {"passed": expected, "workers": workers, "conflicting": conflicting,
            "accepted": accepted, "conflicts": conflicts,
            "storage_errors": storage_errors, "ledger_records": records,
            "committed": committed, "pending": pending, "distinct_digests": distinct}


def run(trials=20, workers=4):
    if not 1 <= trials <= 1000 or not 2 <= workers <= 16:
        raise ValueError("trials must be 1..1000 and workers 2..16")
    with tempfile.TemporaryDirectory() as root:
        observations = [
            campaign_trial(Path(root) / str(i), workers, conflicting=bool(i % 2))
            for i in range(trials)]
    return {"environment": "local-threaded-separate-sqlite-connections",
            "not_blockchain_finality": True, "trials": trials,
            "all_assertions_passed": all(row["passed"] for row in observations),
            "observations": observations}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    result = run(args.trials, args.workers)
    print(json.dumps(result, sort_keys=True))
    if not result["all_assertions_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
