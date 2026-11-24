"""Separate design adjudication and trust sensitivity regression checks."""
import unittest

from experiments.claim_validation.consensus_probe import trial as consensus_trial
from experiments.claim_validation.identity_probe import trial as identity_trial
from experiments.claim_validation.design_reference import adjudicate
from experiments.claim_validation.design_analysis import scenario_result, sensitivity, paired_contrasts
from experiments.claim_validation.paired_comparison import paired_row


class DesignReferenceTests(unittest.TestCase):
    def test_consensus_recomputes_transitions_for_all_conditions(self):
        for n in range(4):
            for allowed in (True, False):
                row = consensus_trial(3, n, allowed)
                ref = adjudicate("consensus", row)
                self.assertTrue(ref["direct_agrees"])
                self.assertEqual(ref["truth"], allowed or n >= 2)

    def test_reference_disagreement_not_hidden(self):
        row = consensus_trial(0, 0, False)
        row["final_status"] = "ACCEPTED"
        self.assertFalse(adjudicate("consensus", row)["direct_agrees"])
        result = scenario_result("consensus", row)
        self.assertFalse(result["reference_channels_agree"])

    def test_identity_config_oracle(self):
        for config in ("registry_strict", "global_declared_deny", "unconfigured_deny"):
            for challenge in ("enrolled_valid", "enrolled_wrong", "unlisted_shared", "unlisted_wrong"):
                row = identity_trial(config, challenge, 0)
                ref = adjudicate("identity", row)
                self.assertTrue(ref["direct_agrees"])
                self.assertEqual(ref["truth"], config == "registry_strict" and challenge == "enrolled_valid")

    def test_contrary_observer_reports_limitation(self):
        row = consensus_trial(0, 0, False)
        out = sensitivity("consensus", row, adjudicate("consensus", row))
        self.assertTrue(out["false_eligibility"])
        self.assertEqual(out["clean_gate"], "NOT_SUPPORTED")

    def test_observer_does_not_override_non_strong_posture(self):
        row = identity_trial("registry_strict", "enrolled_wrong", 0)
        result = sensitivity("identity", row, adjudicate("identity", row))
        self.assertFalse(result["false_eligibility"])

    def test_equal_cell_weight_not_pseudoreplication(self):
        a = identity_trial("registry_strict", "enrolled_valid", 0)
        b = identity_trial("registry_declared_open", "enrolled_valid", 0)
        rows = [{**paired_row("identity", x, "clean"),
                 "design_truth": True, "design_cell": adjudicate("identity", x)["cell"]}
                for x in (a, a, a, b)]
        result = next(r for r in paired_contrasts(rows) if r["fault"] == "clean"
                      and r["comparator"] == "declared_capability_proxy" and r["reference_positive"])
        self.assertEqual(result["design_cells"], 2)
        self.assertEqual(result["gate_minus_comparator_eligibility"], .5)


if __name__ == "__main__":
    unittest.main()
