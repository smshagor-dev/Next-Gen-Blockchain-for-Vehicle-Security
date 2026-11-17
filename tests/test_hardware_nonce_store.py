"""Durable nonce replay regression tests (no hardware access required)."""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hardware_nonce_store import NonceStoreError, SQLiteNonceStore


class DurableNonceTests(unittest.TestCase):
    def test_explicit_provisioning_and_restart_replay(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nonce.db")
            with self.assertRaises(NonceStoreError):
                SQLiteNonceStore(path)
            first = SQLiteNonceStore(path, provision=True)
            self.assertTrue(first.claim("node-1", "a" * 32, ttl_seconds=30))
            first.close()
            recovered = SQLiteNonceStore(path)
            self.assertFalse(recovered.claim("node-1", "a" * 32, ttl_seconds=30))
            self.assertTrue(recovered.claim("node-2", "a" * 32, ttl_seconds=30))
            recovered.close()

    def test_unrelated_sqlite_database_is_not_provisioned_on_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "other.db")
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE unrelated(x INTEGER)")
            with self.assertRaises(NonceStoreError):
                SQLiteNonceStore(path)
            with sqlite3.connect(path) as db:
                self.assertIsNone(db.execute(
                    "SELECT name FROM sqlite_master WHERE name='nonce_claims'"
                ).fetchone())

    def test_claims_not_erased_by_clock_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nonce.db")
            now = [1000.]
            store = SQLiteNonceStore(path, provision=True, clock=lambda: now[0])
            self.assertTrue(store.claim("node", "b" * 32, ttl_seconds=5))
            now[0] = 1.
            self.assertFalse(store.claim("node", "b" * 32, ttl_seconds=5))
            store.close()


if __name__ == "__main__":
    unittest.main()
