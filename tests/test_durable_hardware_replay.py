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

    def test_clock_rollback_rejected_across_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "clock.db")
            with patch("durable_hardware_replay.time.time", return_value=200.0):
                first = DurableNonceStore(path, max_entries_per_device=2)
                self.assertIsNone(first.claim("pi", "a", window_seconds=30))
                first.close()
            with patch("durable_hardware_replay.time.time", return_value=199.0):
                second = DurableNonceStore(path, max_entries_per_device=2)
                self.assertEqual(second.claim("pi", "b", window_seconds=30), "HW_REPLAY_CLOCK_ROLLBACK")
                second.close()
            with patch("durable_hardware_replay.time.time", return_value=201.0):
                third = DurableNonceStore(path, max_entries_per_device=2)
                self.assertEqual(third.claim("pi", "a", window_seconds=30), "HW_REPLAY_DETECTED")
                self.assertIsNone(third.claim("pi", "b", window_seconds=30))
                third.close()

    def test_invalid_capacity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for value in (0, -1, True, 1.5):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    DurableNonceStore(str(Path(d) / "bad.db"), max_entries_per_device=value)

    def test_invalid_window_rejected_without_claim(self):
        with tempfile.TemporaryDirectory() as d:
            store = DurableNonceStore(str(Path(d) / "window.db"), max_entries_per_device=2)
            for value in (0, -2, True, 1.2):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    store.claim("pi", "a", window_seconds=value)
            self.assertIsNone(store.claim("pi", "a", window_seconds=30))
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
