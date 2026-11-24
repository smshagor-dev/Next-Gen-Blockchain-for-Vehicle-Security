"""SIGKILL inside an uncommitted SQLite ledger transaction (non-actuating surrogate).

Unlike the post-commit SIGKILL control, this experiment kills a child after
INSERT but before COMMIT. Parent verifies rollback, then retries the same event.
This does not establish blockchain finality or physical power-loss durability.
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

from research_contracts.sigkill_ledger_recovery import SqliteAtomicLedgerSurrogate

def _child(inbox_path, ledger_path, marker_path):
    inbox = DurableEventInbox(inbox_path)
    ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    try:
        # Durable pending claim is established before ledger append.
        from research_contracts.ledger_inbox_reconciliation import event_id
        # Use the reconciler's real append path, but intercept the SQLite
        # connection at the transaction boundary via an explicit transaction.
        # Pre-stage the inbox using the same public API as reconciliation.
        LedgerReconciler(inbox, ledger).reconcile(DEVICE, NONCE, PAYLOAD,
                                                 after_append=lambda: None)
    finally:
        inbox.close()
        ledger.close()
    raise RuntimeError("unused child path")


def _kill_in_transaction(ledger_path, marker_path):
    # Child is intentionally limited to a SQLite surrogate; never a real ledger.
    db = sqlite3.connect(str(ledger_path), isolation_level=None, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("BEGIN IMMEDIATE")
    db.execute("INSERT INTO events(identity,digest,reference) VALUES (?,?,?)",
               ("uncommitted-probe", "probe-digest", "probe-reference"))
    # Marker is written only after INSERT succeeds; transaction remains open.
    Path(marker_path).write_text("inserted-before-commit", encoding="utf-8")
    os.kill(os.getpid(), signal.SIGKILL)
    raise AssertionError("SIGKILL unexpectedly returned")


def trial(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    ledger_path = directory / "ledger.sqlite"
    marker = directory / "transaction.marker"
    ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    ledger.close()
    proc = subprocess.run(
        [sys.executable, "-m", "research_contracts.inflight_sqlite_sigkill",
         "--child", str(ledger_path), str(marker)],
        capture_output=True, timeout=15)
    if proc.returncode != -signal.SIGKILL or not marker.exists():
        raise AssertionError("inflight kill not reached: " +
                             proc.stderr.decode(errors="replace")[-500:])
    ledger = SqliteAtomicLedgerSurrogate(ledger_path)
    try:
        rolled_back = ledger.count() == 0
        if not rolled_back:
            raise AssertionError("uncommitted row survived SIGKILL")
        reference = ledger.append_once("uncommitted-probe", "probe-digest")
        repeated = ledger.append_once("uncommitted-probe", "probe-digest")
        count = ledger.count()
        if count != 1 or reference != repeated:
            raise AssertionError("retry was not idempotent")
        return {"kill_returncode": proc.returncode, "uncommitted_row_rolled_back": rolled_back,
                "records_after_retry": count, "idempotent_retry": reference == repeated}
    finally:
        ledger.close()


def run(trials=10):
    if not 1 <= trials <= 100:
        raise ValueError("trials must be 1..100")
    with tempfile.TemporaryDirectory() as root:
        rows = [trial(Path(root) / str(i)) for i in range(trials)]
    return {"environment": "sqlite-wal-local-process", "not_blockchain_finality": True,
            "trials": trials, "all_assertions_passed": all(
                row["uncommitted_row_rolled_back"] and row["idempotent_retry"]
                for row in rows), "observations": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--child", nargs=2)
    args = parser.parse_args()
    if args.child:
        _kill_in_transaction(*args.child)
        return
    result = run(args.trials)
    print(json.dumps(result, sort_keys=True))
    if not result["all_assertions_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
