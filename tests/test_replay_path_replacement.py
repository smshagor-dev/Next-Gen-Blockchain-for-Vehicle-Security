"""Non-actuating replay-store path substitution regression controls."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from durable_hardware_replay import DurableNonceStore


class ReplayPathReplacementTests(unittest.TestCase):
    def test_unlinked_database_fails_closed_while_connection_is_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.sqlite"
            store = DurableNonceStore(str(path), max_entries_per_device=8)
            try:
                self.assertIsNone(store.claim("node", "a" * 32, window_seconds=3600))
                os.unlink(path)
                with self.assertRaisesRegex(sqlite3.DatabaseError, "path unavailable"):
                    store.claim("node", "b" * 32, window_seconds=3600)
            finally:
                store.close()

    def test_atomic_replacement_with_valid_historical_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.sqlite"
            replacement = Path(tmp) / "old.sqlite"
            store = DurableNonceStore(str(path), max_entries_per_device=8)
            try:
                self.assertIsNone(store.claim("node", "a" * 32, window_seconds=3600))
                with sqlite3.connect(str(replacement)) as target:
                    store._db.backup(target)
                self.assertIsNone(store.claim("node", "b" * 32, window_seconds=3600))
                os.replace(replacement, path)
                with self.assertRaisesRegex(sqlite3.DatabaseError, "identity changed"):
                    store.claim("node", "c" * 32, window_seconds=3600)
            finally:
                store.close()

    def test_normal_claims_do_not_trip_identity_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableNonceStore(str(Path(tmp) / "replay.sqlite"), max_entries_per_device=8)
            try:
                self.assertIsNone(store.claim("node", "a" * 32, window_seconds=3600))
                self.assertEqual(store.claim("node", "a" * 32, window_seconds=3600), "HW_REPLAY_DETECTED")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
