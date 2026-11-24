"""Surrogate fault-control contract; does not assert blockchain finality."""
import tempfile
import unittest
from pathlib import Path
from research_contracts.overlap_sigkill_control import run, trial

class OverlapSigkillTests(unittest.TestCase):
    def test_precommit_kill_and_surviving_writer(self):
        with tempfile.TemporaryDirectory() as root:
            result = trial(Path(root))
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["victim_exit"], -9)
        self.assertEqual(result["rows"], [("event-1","digest-1")])

    def test_multiple_independent_process_trials(self):
        result = run(2)
        self.assertTrue(result["all_assertions_passed"], result)
        self.assertEqual(len(result["observations"]), 2)

    def test_invalid_trial_bounds(self):
        for count in (0, 101):
            with self.subTest(count=count):
                with self.assertRaises(ValueError):
                    run(count)

if __name__ == "__main__":
    unittest.main()
