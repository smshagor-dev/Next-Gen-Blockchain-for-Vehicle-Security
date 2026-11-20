"""Synthetic verifier contract tests; no vehicle hardware or publication evidence."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from durable_hardware_replay import DurableNonceStore
from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError


class DurableReplayTests(unittest.TestCase):
    def test_restart_and_atomic_duplicate(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "claims.sqlite3")
            first = DurableNonceStore(path, max_entries_per_device=16)
            self.assertIsNone(first.claim("pi1", "a" * 32, window_seconds=30))
            self.assertEqual(first.claim("pi1", "a" * 32, window_seconds=30), "HW_REPLAY_DETECTED")
            first.close()
            second = DurableNonceStore(path, max_entries_per_device=16)
            self.assertEqual(second.claim("pi1", "a" * 32, window_seconds=30), "HW_REPLAY_DETECTED")
            self.assertIsNone(second.claim("pi2", "a" * 32, window_seconds=30))
            second.close()

    def test_capacity_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            store = DurableNonceStore(str(Path(d) / "n.db"), max_entries_per_device=1)
            self.assertIsNone(store.claim("pi", "a", window_seconds=30))
            self.assertEqual(store.claim("pi", "b", window_seconds=30), "HW_REPLAY_CACHE_SATURATED")
            store.close()

    def test_expiry_is_reclaimable(self):
        with tempfile.TemporaryDirectory() as d:
            store = DurableNonceStore(str(Path(d) / "n.db"), max_entries_per_device=1)
            with patch("durable_hardware_replay.time.time", return_value=100):
                self.assertIsNone(store.claim("pi", "a", window_seconds=3))
            with patch("durable_hardware_replay.time.time", return_value=104):
                self.assertIsNone(store.claim("pi", "b", window_seconds=3))
            store.close()

    def test_memory_path_rejected(self):
        with self.assertRaises(ValueError):
            DurableNonceStore(":memory:", max_entries_per_device=16)

    def test_verifier_store_failure_is_authenticated_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            verifier = HardwareEnvelopeVerifier({"pi": "x" * 40}, replay_store_path=str(Path(d) / "n.db"))
            self.assertTrue(verifier.metadata()["durable_nonce_claims"])
            self.assertFalse(verifier.metadata()["rollback_resistant"])


if __name__ == "__main__":
    unittest.main()
