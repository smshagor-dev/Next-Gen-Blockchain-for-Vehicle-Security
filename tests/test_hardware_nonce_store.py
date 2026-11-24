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

    def test_capacity_exhaustion_denies_without_eviction(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nonce.db")
            store = SQLiteNonceStore(path, provision=True, max_claims=2)
            self.assertTrue(store.claim("node", "a" * 32, ttl_seconds=1))
            self.assertTrue(store.claim("node", "b" * 32, ttl_seconds=1))
            with self.assertRaisesRegex(NonceStoreError, "capacity exhausted"):
                store.claim("node", "c" * 32, ttl_seconds=1)
            self.assertFalse(store.claim("node", "a" * 32, ttl_seconds=1))
            store.close()
            recovered = SQLiteNonceStore(path, max_claims=2)
            self.assertFalse(recovered.claim("node", "b" * 32, ttl_seconds=1))
            recovered.close()

    def test_provisioning_existing_database_denied_without_reset(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nonce.db")
            original = SQLiteNonceStore(path, provision=True)
            self.assertTrue(original.claim("node", "a" * 32, ttl_seconds=30))
            original.close()
            with self.assertRaisesRegex(NonceStoreError, "already exists"):
                SQLiteNonceStore(path, provision=True)
            recovered = SQLiteNonceStore(path)
            self.assertFalse(recovered.claim("node", "a" * 32, ttl_seconds=30))
            recovered.close()

    def test_provisioning_existing_unrelated_database_denied(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "unrelated.db")
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE unrelated(x INTEGER)")
            with self.assertRaisesRegex(NonceStoreError, "already exists"):
                SQLiteNonceStore(path, provision=True)
            with sqlite3.connect(path) as db:
                self.assertIsNone(db.execute(
                    "SELECT name FROM sqlite_master WHERE name='nonce_claims'"
                ).fetchone())

    def test_invalid_clock_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            store = SQLiteNonceStore(os.path.join(d, "nonce.db"),
                                     provision=True, clock=lambda: float("nan"))
            with self.assertRaisesRegex(NonceStoreError, "clock"):
                store.claim("node", "a" * 32, ttl_seconds=30)
            store.close()

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
