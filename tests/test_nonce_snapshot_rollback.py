"""Negative-control experiment: local SQLite nonce durability is not rollback resistance.

Only temporary local databases are used. This intentionally demonstrates that
an attacker with filesystem restore privileges can replay a previously accepted
authenticated nonce after restoring an older, valid SQLite snapshot. It does
not test remote network attackers, vehicle hardware, or ledger finality.
"""
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from hardware_nonce_store import SQLiteNonceStore

DEVICE = "vehicle-test"
NONCE_A = "a" * 32
NONCE_B = "b" * 32


def checkpoint_snapshot(source: Path, destination: Path):
    """Take a transactionally consistent SQLite snapshot, not a raw WAL copy."""
    with sqlite3.connect(str(source)) as connection:
        with sqlite3.connect(str(destination)) as snapshot:
            connection.backup(snapshot)


def restore_snapshot(snapshot: Path, destination: Path):
    """Only restore a *closed* database; discard any old WAL/SHM sidecars."""
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(destination) + suffix)
        if candidate.exists():
            candidate.unlink()
    shutil.copyfile(snapshot, destination)


class NonceRollbackNegativeControl(unittest.TestCase):
    def test_restart_preserves_claim_without_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "nonce.sqlite"
            store = SQLiteNonceStore(str(db), provision=True)
            try:
                self.assertTrue(store.claim(DEVICE, NONCE_A, ttl_seconds=300))
            finally:
                store.close()
            reopened = SQLiteNonceStore(str(db))
            try:
                self.assertFalse(reopened.claim(DEVICE, NONCE_A, ttl_seconds=300))
            finally:
                reopened.close()

    def test_valid_snapshot_rollback_reopens_replay_window(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "nonce.sqlite"
            snapshot = Path(temp) / "snapshot.sqlite"
            store = SQLiteNonceStore(str(db), provision=True)
            store.close()
            checkpoint_snapshot(db, snapshot)

            store = SQLiteNonceStore(str(db))
            try:
                self.assertTrue(store.claim(DEVICE, NONCE_A, ttl_seconds=300))
                self.assertTrue(store.claim(DEVICE, NONCE_B, ttl_seconds=300))
            finally:
                store.close()

            before = SQLiteNonceStore(str(db))
            try:
                self.assertFalse(before.claim(DEVICE, NONCE_A, ttl_seconds=300))
            finally:
                before.close()

            restore_snapshot(snapshot, db)
            after = SQLiteNonceStore(str(db))
            try:
                # Expected *negative* security outcome: a valid old snapshot
                # passes integrity_check but forgets both accepted nonces.
                self.assertTrue(after.claim(DEVICE, NONCE_A, ttl_seconds=300))
                self.assertTrue(after.claim(DEVICE, NONCE_B, ttl_seconds=300))
            finally:
                after.close()

    def test_corrupt_snapshot_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "nonce.sqlite"
            store = SQLiteNonceStore(str(db), provision=True)
            store.close()
            db.write_bytes(b"not a sqlite database")
            with self.assertRaises((sqlite3.DatabaseError, RuntimeError)):
                SQLiteNonceStore(str(db))


if __name__ == "__main__":
    unittest.main()
