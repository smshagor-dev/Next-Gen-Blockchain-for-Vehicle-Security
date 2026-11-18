"""Regression assertions for the non-actuating ledger fault negative control."""
import unittest
from research_contracts.ledger_failure_retransmission_control import run_case


class LedgerFailureRetransmissionTests(unittest.TestCase):
    def test_failure_after_replay_claim_burns_retransmission(self):
        result = run_case(True)
        self.assertEqual(result["attempts"], [
            "INJECTED_LEDGER_WRITE_FAILURE", "HW_REPLAY_DETECTED"
        ])
        self.assertEqual(result["committed_count"], 0)
        self.assertTrue(result["lost_valid_observation"])

    def test_control_commits_once_and_rejects_duplicate(self):
        result = run_case(False)
        self.assertEqual(result["attempts"], ["committed", "HW_REPLAY_DETECTED"])
        self.assertEqual(result["committed_count"], 1)
        self.assertFalse(result["lost_valid_observation"])


if __name__ == "__main__":
    unittest.main()
