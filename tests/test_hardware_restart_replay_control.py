"""Non-actuating subprocess replay persistence counterexample tests."""
import unittest
from research_contracts.hardware_restart_replay_control import run_control


class RestartReplayNegativeControlTests(unittest.TestCase):
    def test_same_process_replay_is_rejected(self):
        self.assertTrue(run_control()["same_process_replay_rejected"])

    def test_new_process_reaccepts_identical_envelope(self):
        result = run_control()
        self.assertTrue(result["accepted_after_restart"])
        self.assertFalse(result["physical_actuation"])
        self.assertEqual(result["claim_scope"], "negative_control_only")


if __name__ == "__main__":
    unittest.main()
