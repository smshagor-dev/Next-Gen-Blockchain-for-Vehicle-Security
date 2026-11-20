"""Non-actuating durable replay corruption negative controls."""
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from durable_hardware_replay import DurableNonceStore


class ReplayCorruptionControls(unittest.TestCase):
    def test_clean_store_reopens_and_rejects_previous_nonce(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "replay.db")
            store = DurableNonceStore(path, max_entries_per_device=4)
            try:
                self.assertIsNone(store.claim("pi-1", "ab" * 16, window_seconds=60))
            finally:
                store.close()
            restarted = DurableNonceStore(path, max_entries_per_device=4)
            try:
                self.assertEqual(
                    restarted.claim("pi-1", "ab" * 16, window_seconds=60),
                    "HW_REPLAY_DETECTED",
                )
            finally:
                restarted.close()

    def test_deleted_nonce_table_fails_closed_instead_of_reinitializing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "replay.db")
            store = DurableNonceStore(path, max_entries_per_device=4)
            self.assertIsNone(store.claim("pi-1", "ab" * 16, window_seconds=60))
            store.close()
            # Valid SQLite snapshot with deleted replay state: quick_check
            # alone reports ok. Recreating the table would permit replay.
            with sqlite3.connect(path) as db:
                db.execute("DROP TABLE nonce_claims")
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute("PRAGMA quick_check").fetchone(), ("ok",))
            with self.assertRaises(sqlite3.DatabaseError):
                DurableNonceStore(path, max_entries_per_device=4)

    def test_deleted_clock_table_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "replay.db")
            store = DurableNonceStore(path, max_entries_per_device=4)
            store.close()
            with sqlite3.connect(path) as db:
                db.execute("DROP TABLE replay_clock")
            with self.assertRaises(sqlite3.DatabaseError):
                DurableNonceStore(path, max_entries_per_device=4)

    def test_preexisting_empty_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.db"
            path.touch()
            with self.assertRaisesRegex(sqlite3.DatabaseError, "empty"):
                DurableNonceStore(str(path), max_entries_per_device=4)
            self.assertEqual(path.stat().st_size, 0)

    def test_truncated_committed_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.db"
            store = DurableNonceStore(str(path), max_entries_per_device=4)
            self.assertIsNone(store.claim("pi-1", "ab" * 16, window_seconds=60))
            store.close()
            path.write_bytes(b"")
            with self.assertRaises(sqlite3.DatabaseError):
                DurableNonceStore(str(path), max_entries_per_device=4)

    def test_new_missing_path_initializes_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.db"
            self.assertFalse(path.exists())
            store = DurableNonceStore(str(path), max_entries_per_device=4)
            try:
                self.assertIsNone(store.claim("pi-1", "ab" * 16, window_seconds=60))
            finally:
                store.close()
            self.assertTrue(path.exists())

    def test_corrupt_database_header_rejects_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.db"
            store = DurableNonceStore(str(path), max_entries_per_device=4)
            store.close()
            # Deliberately damage a test-only database, never a production DB.
            with path.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"NOT_A_SQLITE_DATABASE")
            with self.assertRaises(sqlite3.DatabaseError):
                DurableNonceStore(str(path), max_entries_per_device=4)


if __name__ == "__main__":
    unittest.main()
