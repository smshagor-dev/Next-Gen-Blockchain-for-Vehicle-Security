"""Negative controls: generation reset must not erase local prefix evidence."""
import unittest
from unittest import mock

import ledger_integrity
from ledger_integrity import GoLedgerSnapshotVerifier, LedgerIntegrityError
from research_contracts.go_generation_rollback_control import CrossGenerationPrefixMonitor


def blocks(*names):
    return [{"block_hash": name, "index": i, "vehicle_id": "v"} for i, name in enumerate(names)]


class GenerationRollbackControls(unittest.TestCase):
    def setUp(self):
        # Isolate generation/reset logic from hash correctness; a separate
        # verifier test suite covers actual Go block hashing and linkage.
        patcher = mock.patch.object(ledger_integrity, "verify_go_block", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_existing_generation_reset_forgets_previous_prefix(self):
        verifier = GoLedgerSnapshotVerifier("v")
        self.assertTrue(verifier.verify_and_track(blocks("a", "b"), "service-A"))
        # Counterexample: shorter chain accepted when generation changes.
        self.assertTrue(verifier.verify_and_track(blocks("a"), "service-B"))

    def test_monitor_rejects_generation_truncation(self):
        monitor = CrossGenerationPrefixMonitor("v")
        self.assertTrue(monitor.verify(blocks("a", "b"), "service-A"))
        with self.assertRaisesRegex(LedgerIntegrityError, "truncation"):
            monitor.verify(blocks("a"), "service-B")
        self.assertEqual(monitor.observed_blocks, 2)

    def test_monitor_rejects_rewritten_history_on_new_generation(self):
        monitor = CrossGenerationPrefixMonitor("v")
        monitor.verify(blocks("a", "b"), "service-A")
        with self.assertRaisesRegex(LedgerIntegrityError, "prefix mutation"):
            monitor.verify(blocks("x", "b"), "service-B")
        self.assertEqual(monitor.observed_blocks, 2)

    def test_monitor_accepts_unchanged_prefix_and_append(self):
        monitor = CrossGenerationPrefixMonitor("v")
        monitor.verify(blocks("a"), "service-A")
        self.assertTrue(monitor.verify(blocks("a", "b"), "service-B"))
        self.assertEqual(monitor.observed_blocks, 2)

    def test_invalid_snapshot_does_not_advance_pins(self):
        monitor = CrossGenerationPrefixMonitor("v")
        with mock.patch.object(monitor.verifier, "verify_and_track", side_effect=LedgerIntegrityError("invalid")):
            with self.assertRaises(LedgerIntegrityError):
                monitor.verify(blocks("a"), "service-A")
        self.assertEqual(monitor.observed_blocks, 0)


if __name__ == "__main__":
    unittest.main()
