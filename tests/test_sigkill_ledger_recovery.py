"""Regression checks for real child-process termination at the cross-store boundary."""
import tempfile
import unittest
from pathlib import Path

from research_contracts.sigkill_ledger_recovery import trial


class SigkillLedgerRecoveryTests(unittest.TestCase):
    def test_sigkill_after_append_recovers_without_second_record(self):
        with tempfile.TemporaryDirectory() as root:
            observation = trial(Path(root) / "single")
        self.assertEqual(observation["kill_returncode"], -9)
        self.assertEqual(observation["pending_before"], 1)
        self.assertEqual(observation["ledger_records_before"], 1)
        self.assertEqual(observation["ledger_records_after"], 1)
        self.assertEqual(observation["recovery"], "RECOVERED")
        self.assertEqual(observation["second_retry"], "COMMITTED")

    def test_independent_fresh_trial_directories(self):
        with tempfile.TemporaryDirectory() as root:
            observations = [trial(Path(root) / str(i)) for i in range(3)]
        self.assertEqual(len(observations), 3)
        self.assertTrue(all(row["ledger_records_after"] == 1 for row in observations))


if __name__ == "__main__":
    unittest.main()
