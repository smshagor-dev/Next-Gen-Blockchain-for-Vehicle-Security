"""Non-actuating independent-process contention contract checks."""
import tempfile
import unittest
from pathlib import Path

from research_contracts.process_ledger_recovery import trial, run


class ProcessLedgerRecoveryTests(unittest.TestCase):
    def test_independent_process_same_event(self):
        with tempfile.TemporaryDirectory() as root:
            result = trial(Path(root), workers=3)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["ledger_records"], 1)
        self.assertEqual(result["setup_failures"], [])
        self.assertFalse(result["timed_out"])

    def test_independent_process_conflicting_payload(self):
        with tempfile.TemporaryDirectory() as root:
            result = trial(Path(root), workers=4, conflicting=True)
        self.assertTrue(result["passed"], result)
        self.assertIn("conflict", [kind for _, kind in result["outcomes"]])
        self.assertEqual(result["setup_failures"], [])

    def test_repeated_mixed_process_campaign(self):
        result = run(trials=4, workers=3)
        self.assertTrue(result["all_assertions_passed"], result)

    def test_invalid_limits(self):
        with self.assertRaises(ValueError):
            run(trials=0)
        with self.assertRaises(ValueError):
            run(workers=17)


if __name__ == "__main__":
    unittest.main()
