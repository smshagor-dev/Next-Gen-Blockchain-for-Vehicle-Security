"""Paired replay controls, using actual local trial traces where available."""
import unittest

from experiments.claim_validation.consensus_probe import trial as consensus_trial
from experiments.claim_validation.identity_probe import trial as identity_trial
from experiments.claim_validation.paired_comparison import paired_row, summarize, FAULTS, METHODS


class PairedComparisonTests(unittest.TestCase):
    def test_actual_consensus_negative(self):
        row = consensus_trial(0, 0, False)
        result = paired_row("consensus", row, "clean")
        self.assertFalse(result["reference_supported"])
        self.assertEqual(result["posture_proxy"], "ELIGIBLE")
        self.assertEqual(result["observed_gate"], "NOT_SUPPORTED")

    def test_actual_identity_positive_and_unlisted(self):
        positive = paired_row("identity", identity_trial("registry_strict", "enrolled_valid", 0), "clean")
        negative = paired_row("identity", identity_trial("global_declared_deny", "unlisted_shared", 0), "clean")
        self.assertTrue(positive["reference_supported"])
        self.assertEqual(positive["observed_gate"], "ELIGIBLE")
        self.assertFalse(negative["reference_supported"])
        self.assertEqual(negative["observed_gate"], "NOT_SUPPORTED")

    def test_age_scope_ablation(self):
        row = identity_trial("registry_strict", "enrolled_valid", 0)
        for fault in ("stale", "future", "wrong_scope"):
            result = paired_row("identity", row, fault)
            self.assertEqual(result["observed_gate"], "WITHHELD")
            self.assertEqual(result["without_scope_freshness"], "ELIGIBLE")

    def test_missing_wrong_kind_and_schema_remain_withheld(self):
        row = identity_trial("registry_strict", "enrolled_valid", 0)
        for fault in ("missing", "wrong_kind", "malformed"):
            result = paired_row("identity", row, fault)
            self.assertEqual(result["observed_gate"], "WITHHELD")
            self.assertEqual(result["without_scope_freshness"], "WITHHELD")

    def test_metadata_disagreement_not_oracle(self):
        row = identity_trial("registry_strict", "enrolled_valid", 0)
        result = paired_row("identity", row, "metadata_disagreement")
        self.assertEqual(result["declared_capability_proxy"], "WITHHELD")
        self.assertEqual(result["observed_gate"], "ELIGIBLE")
        self.assertTrue(result["reference_supported"])

    def test_digest_mismatch_rejected(self):
        row = identity_trial("registry_strict", "enrolled_valid", 0)
        row["runtime_evidence"]["facts"]["registry_size"] = 99
        with self.assertRaises(ValueError):
            paired_row("identity", row, "clean")

    def test_metrics_keep_unknown_outcomes(self):
        row = identity_trial("registry_strict", "enrolled_valid", 0)
        report = summarize([paired_row("identity", row, fault) for fault in FAULTS])
        self.assertEqual(len(report), len(FAULTS)*len(METHODS))
        stale = next(r for r in report if r["fault"] == "stale" and r["method"] == "observed_gate")
        self.assertEqual(stale["positive_withheld"], 1)
        self.assertIsNone(stale["unsupported_eligibility_rate"])


if __name__ == "__main__":
    unittest.main()
