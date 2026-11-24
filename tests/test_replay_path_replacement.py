"""Non-actuating replay-store path substitution regression controls."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from hardware_nonce_store import SQLiteNonceStore, NonceStoreError


class ReplayPathReplacementTests(unittest.TestCase):
    def test_unlinked_database_fails_closed_while_connection_is_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.sqlite"
            store = SQLiteNonceStore(str(path), provision=True, max_claims=8)
            try:
                self.assertTrue(store.claim("node", "a" * 32, ttl_seconds=600))
                try:
                    os.unlink(path)
                except PermissionError:
                    self.skipTest("platform prevents unlinking an open database")
                with self.assertRaisesRegex(NonceStoreError, "path unavailable"):
                    store.claim("node", "b" * 32, ttl_seconds=600)
            finally:
                store.close()

    def test_atomic_replacement_with_valid_historical_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.sqlite"
            replacement = Path(tmp) / "old.sqlite"
            store = SQLiteNonceStore(str(path), provision=True, max_claims=8)
            try:
                self.assertTrue(store.claim("node", "a" * 32, ttl_seconds=600))
                target = sqlite3.connect(str(replacement))
                try:
                    store._db.backup(target)
                finally:
                    target.close()
                self.assertTrue(store.claim("node", "b" * 32, ttl_seconds=600))
                try:
                    os.replace(replacement, path)
                except PermissionError:
                    self.skipTest("platform prevents replacing an open database")
                with self.assertRaisesRegex(NonceStoreError, "identity changed"):
                    store.claim("node", "c" * 32, ttl_seconds=600)
            finally:
                store.close()

    def test_normal_claims_do_not_trip_identity_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteNonceStore(str(Path(tmp) / "replay.sqlite"), provision=True, max_claims=8)
            try:
                self.assertTrue(store.claim("node", "a" * 32, ttl_seconds=600))
                self.assertFalse(store.claim("node", "a" * 32, ttl_seconds=600))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
