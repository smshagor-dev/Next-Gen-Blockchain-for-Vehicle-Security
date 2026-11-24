"""Local identity admission experiment controls."""
import unittest

from experiments.claim_validation.identity_probe import trial


class IdentityClaimProbeTests(unittest.TestCase):
    def test_registry_positive_control(self):
        self.assertTrue(trial("registry_strict", "enrolled_valid", 0)["authenticated_ack"])

    def test_registry_rejects_unlisted_even_with_compatibility_flag(self):
        for config in ("registry_strict", "registry_with_compatibility"):
            row = trial(config, "unlisted_shared", 0)
            self.assertFalse(row["authenticated_ack"])
            self.assertFalse(row["bound_identity"])
            self.assertIn("HANDSHAKE_REJECTED", row["observed_reasons"])

    def test_unconfigured_denies(self):
        self.assertFalse(trial("unconfigured_deny", "unlisted_shared", 0)["authenticated_ack"])

    def test_explicit_lab_mode_is_not_enrollment(self):
        row = trial("global_lab", "unlisted_shared", 0)
        self.assertTrue(row["authenticated_ack"])
        self.assertTrue(row["unlisted_identity_accepted"])
        self.assertFalse(row["sybil_resistance_metadata"])

    def test_declared_deny_not_same_as_enforced_admission(self):
        row = trial("global_declared_deny", "unlisted_shared", 0)
        self.assertTrue(row["identity_admission_enforced_metadata"])
        self.assertTrue(row["unlisted_identity_accepted"])

    def test_observed_alerts_change_operational_posture(self):
        row = trial("registry_strict", "enrolled_wrong", 0)
        self.assertFalse(row["authenticated_ack"])
        self.assertEqual(row["posture_without_alerts"], "STRONG")
        self.assertEqual(row["posture_with_observed_alerts"], "GUARDED")


if __name__ == "__main__":
    unittest.main()
