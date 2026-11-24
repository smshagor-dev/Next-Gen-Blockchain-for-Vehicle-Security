"""Non-actuating negative control: valid SQLite snapshot rollback defeats nonce history.

This is an intentional counterexample, not a fix or a publishable V2X result.
Only temporary SQLite databases are touched. No sockets or ECU interfaces.
"""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from durable_hardware_replay import DurableNonceStore


class ReplaySnapshotRollbackNegativeControl(unittest.TestCase):
    def test_valid_historical_snapshot_reaccepts_committed_nonce(self):
        with tempfile.TemporaryDirectory() as tmp:
            active = Path(tmp) / "active.sqlite"
            snapshot = Path(tmp) / "historical.sqlite"
            device = "enrolled-pi"
            earlier_nonce = "a" * 32
            later_nonce = "b" * 32

            store = DurableNonceStore(str(active), max_entries_per_device=8)
            try:
                self.assertIsNone(store.claim(device, earlier_nonce, window_seconds=3600))
                # SQLite backup API creates a transaction-consistent snapshot,
                # including committed nonce and high-water clock state.
                backup = sqlite3.connect(str(snapshot))
                try:
                    store._db.backup(backup)
                finally:
                    backup.close()
                self.assertIsNone(store.claim(device, later_nonce, window_seconds=3600))
                self.assertEqual(
                    store.claim(device, later_nonce, window_seconds=3600),
                    "HW_REPLAY_DETECTED",
                )
            finally:
                store.close()

            # Simulate privileged replacement of a valid on-disk snapshot.
            # Remove WAL sidecars before replacement to avoid mixed generations.
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(active) + suffix)
                if sidecar.exists():
                    sidecar.unlink()
            os.replace(snapshot, active)

            reopened = DurableNonceStore(str(active), max_entries_per_device=8)
            try:
                self.assertEqual(
                    reopened.claim(device, earlier_nonce, window_seconds=3600),
                    "HW_REPLAY_DETECTED",
                )
                # This SHOULD be rejected by a rollback-resistant design.
                # Expected acceptance exposes the current trust boundary.
                self.assertIsNone(
                    reopened.claim(device, later_nonce, window_seconds=3600)
                )
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
