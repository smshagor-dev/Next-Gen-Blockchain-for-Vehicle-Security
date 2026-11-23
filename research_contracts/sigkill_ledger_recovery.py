"""Process-level SIGKILL recovery experiment; SQLite ledger is a SURROGATE, not blockchain finality.

Run: python -m research_contracts.sigkill_ledger_recovery --trials 10
No hardware or actuator interaction. Never treat results as main-paper evidence.
"""
import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from research_contracts.durable_event_inbox import DurableEventInbox
from research_contracts.ledger_inbox_reconciliation import LedgerReconciler, event_id


class SqliteAtomicLedgerSurrogate:
    """Separate durable store with atomic append_once, NOT a real consensus ledger."""
    atomic_append_once = True

    def __init__(self, path):
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (identity TEXT PRIMARY KEY, digest TEXT NOT NULL, reference TEXT NOT NULL)")

    def lookup(self, identity):
        row = self.db.execute("SELECT digest, reference FROM events WHERE identity=?", (identity,)).fetchone()
        return tuple(row) if row else None

    def append_once(self, identity, digest):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.lookup(identity)
            if row is None:
                reference = "surrogate:" + identity
                self.db.execute("INSERT INTO events VALUES (?,?,?)", (identity, digest, reference))
            else:
                if row[0] != digest:
                    raise ValueError("conflicting event digest")
                reference = row[1]
            self.db.execute("COMMIT")
            return reference
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def count(self):
        return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self):
        self.db.close()


def child(inbox_path, ledger_path, marker_path):
    inbox = DurableEventInbox(inbox_path)
    ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    def kill_after_append():
        # Marker is only for diagnosis; durable ledger commit already happened.
        Path(marker_path).write_text("after-append", encoding="utf-8")
        os.kill(os.getpid(), signal.SIGKILL)
    LedgerReconciler(inbox, ledger).reconcile(
        "test-pi", "nonce-001", {"speed": 3}, after_append=kill_after_append)
    raise AssertionError("SIGKILL did not terminate process")


def trial(directory):
    directory.mkdir(parents=True, exist_ok=True)
    inbox_path, ledger_path, marker = (directory / n for n in ("inbox.sqlite", "ledger.sqlite", "kill.marker"))
    proc = subprocess.run(
        [sys.executable, "-m", "research_contracts.sigkill_ledger_recovery", "--child",
         str(inbox_path), str(ledger_path), str(marker)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if proc.returncode != -signal.SIGKILL or not marker.exists():
        raise AssertionError("child did not reach SIGKILL boundary: " + proc.stderr.decode(errors="replace")[-500:])
    inbox = DurableEventInbox(inbox_path)
    ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    try:
        before = ledger.count()
        pending_before = len(inbox.pending())
        result = LedgerReconciler(inbox, ledger).reconcile("test-pi", "nonce-001", {"speed": 3})
        after = ledger.count()
        again = LedgerReconciler(inbox, ledger).reconcile("test-pi", "nonce-001", {"speed": 3})
        assert (before, pending_before, result, after, again) == (1, 1, "RECOVERED", 1, "COMMITTED")
        return {"kill_returncode": proc.returncode, "pending_before": pending_before,
                "ledger_records_before": before, "recovery": result,
                "ledger_records_after": after, "second_retry": again}
    finally:
        inbox.close()
        ledger.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--child", nargs=3)
    args = parser.parse_args()
    if args.child:
        child(*args.child)
        return
    if not 1 <= args.trials <= 1000:
        parser.error("trials must be 1..1000")
    with tempfile.TemporaryDirectory() as root:
        observations = [trial(Path(root) / str(i)) for i in range(args.trials)]
    print(json.dumps({"environment": "local-process-sqlite-surrogate",
                      "not_blockchain_finality": True, "trials": args.trials,
                      "all_assertions_passed": True, "observations": observations}, sort_keys=True))


if __name__ == "__main__":
    main()
