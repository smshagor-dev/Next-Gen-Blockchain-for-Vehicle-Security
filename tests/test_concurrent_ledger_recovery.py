"""Focused independent-connection concurrency contract checks (SQLite surrogate)."""
import tempfile
import unittest
from pathlib import Path

from research_contracts.concurrent_ledger_recovery import campaign_trial, run


class ConcurrentLedgerRecoveryTests(unittest.TestCase):
    def test_same_authenticated_identity_four_writers(self):
        with tempfile.TemporaryDirectory() as root:
            result = campaign_trial(Path(root), workers=4)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["ledger_records"], 1)
        self.assertEqual(result["committed"], 1)
        self.assertEqual(result["accepted"], 4)

    def test_conflicting_payload_is_not_silently_committed(self):
        with tempfile.TemporaryDirectory() as root:
            result = campaign_trial(Path(root), workers=4, conflicting=True)
        self.assertTrue(result["passed"], result)
        self.assertGreaterEqual(result["conflicts"], 1)
        self.assertEqual(result["distinct_digests"], 1)

    def test_repeated_trials_have_no_missing_commits(self):
        result = run(trials=6, workers=3)
        self.assertTrue(result["all_assertions_passed"], result)

    def test_invalid_trial_bounds(self):
        with self.assertRaises(ValueError):
            run(trials=0)
        with self.assertRaises(ValueError):
            run(workers=17)


if __name__ == "__main__":
    unittest.main()
