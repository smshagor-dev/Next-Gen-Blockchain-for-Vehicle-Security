"""Focused checks for the exploratory actual-engine protocol."""
import unittest

from experiments.claim_validation.consensus_probe import trial


class ClaimValidationConsensusProbeTests(unittest.TestCase):
    def test_policy_disallowed_without_quorum_is_rejected(self):
        for count in (0, 1):
            with self.subTest(count=count):
                result = trial(0, count, False)
                self.assertEqual(result["final_status"], "REJECTED")
                self.assertFalse(result["unsupported_policy_acceptance"])

    def test_controlled_quorum_can_approve_policy_disallowed_proposal(self):
        for count in (2, 3):
            with self.subTest(count=count):
                result = trial(0, count, False)
                self.assertEqual(result["final_status"], "ACCEPTED")
                self.assertTrue(result["unsupported_policy_acceptance"])
                self.assertEqual(result["posture_after"], "STRONG")

    def test_allowed_proposal_positive_control(self):
        result = trial(1, 0, True)
        self.assertEqual(result["final_status"], "ACCEPTED")
        self.assertFalse(result["unsupported_policy_acceptance"])
        self.assertEqual(result["quorum_threshold"], 2)

    def test_arrival_order_does_not_change_fixed_vote_outcome(self):
        for seed in range(4):
            self.assertEqual(trial(seed, 2, False)["final_status"], "ACCEPTED")
            self.assertEqual(trial(seed, 1, False)["final_status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
