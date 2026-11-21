"""Synthetic counterexamples: no physical or independent dataset claims."""
import unittest
from research_contracts.evidence_gate_adversarial_controls import run_case, evaluate_all


class AdversarialControls(unittest.TestCase):
    def test_colluding_enrolled_senders_defeat_quorum(self):
        result = run_case("collusion")
        self.assertFalse(result["truth"])
        self.assertTrue(result["evidence_gate"])

    def test_partition_causes_availability_loss(self):
        result = run_case("partition")
        self.assertTrue(result["truth"])
        self.assertTrue(result["authenticated_only"])
        self.assertFalse(result["evidence_gate"])

    def test_replay_does_not_count_as_distinct_sender(self):
        self.assertFalse(run_case("replay")["evidence_gate"])

    def test_emergency_stop_dominates(self):
        result = run_case("emergency_stop")
        self.assertFalse(result["authenticated_only"])
        self.assertFalse(result["evidence_gate"])

    def test_honest_quorum(self):
        self.assertTrue(run_case("honest")["evidence_gate"])

    def test_all_cases_have_identical_schema(self):
        rows = evaluate_all()
        self.assertEqual(len(rows), 5)
        self.assertEqual(len({tuple(sorted(r)) for r in rows}), 1)

    def test_unknown_case_rejected(self):
        with self.assertRaises(ValueError):
            run_case("unsupported")


if __name__ == "__main__":
    unittest.main()
