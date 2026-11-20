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
