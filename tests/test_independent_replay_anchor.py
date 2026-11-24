"""Non-actuating controls for an independently retained replay anchor."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from durable_hardware_replay import DurableNonceStore
from independent_replay_anchor import AnchoredNonceAdmission, SimulationAnchor


class AnchorProtocolTests(unittest.TestCase):
    def test_snapshot_rollback_is_rejected_while_anchor_survives(self):
        with tempfile.TemporaryDirectory() as tmp:
            active = Path(tmp) / "active.sqlite"
            historical = Path(tmp) / "historical.sqlite"
            anchor = SimulationAnchor()
            store = DurableNonceStore(str(active), max_entries_per_device=8)
            try:
                admission = AnchoredNonceAdmission(store, anchor)
                self.assertIsNone(admission.claim("node", "a" * 32, window_seconds=3600))
                with sqlite3.connect(str(historical)) as backup:
                    store._db.backup(backup)
                self.assertIsNone(admission.claim("node", "b" * 32, window_seconds=3600))
            finally:
                store.close()
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(active) + suffix)
                if sidecar.exists():
                    sidecar.unlink()
            os.replace(historical, active)
            reopened = DurableNonceStore(str(active), max_entries_per_device=8)
            try:
                self.assertEqual(
                    AnchoredNonceAdmission(reopened, anchor).claim(
                        "node", "b" * 32, window_seconds=3600),
                    "HW_ANCHOR_REPLAY_DETECTED")
            finally:
                reopened.close()

    def test_anchor_failure_never_calls_local_store(self):
        class Down:
            def reserve(self, device, nonce_digest):
                raise TimeoutError("anchor unavailable")
        class Spy:
            called = False
            def claim(self, *args, **kwargs):
                self.called = True
        spy = Spy()
        with self.assertRaises(TimeoutError):
            AnchoredNonceAdmission(spy, Down()).claim(
                "node", "a" * 32, window_seconds=3600)
        self.assertFalse(spy.called)

    def test_failed_local_claim_consumes_reservation(self):
        class Rejecting:
            def claim(self, *args, **kwargs):
                raise sqlite3.DatabaseError("disk full")
        anchor = SimulationAnchor()
        admission = AnchoredNonceAdmission(Rejecting(), anchor)
        with self.assertRaises(sqlite3.DatabaseError):
            admission.claim("node", "a" * 32, window_seconds=3600)
        self.assertEqual(admission.claim("node", "a" * 32, window_seconds=3600),
                         "HW_ANCHOR_REPLAY_DETECTED")


if __name__ == "__main__":
    unittest.main()
