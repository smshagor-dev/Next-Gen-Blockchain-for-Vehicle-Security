"""Actual provider and deliberate fallback controls."""
import unittest
from experiments.claim_validation.pqc_probe import require_providers, trial


class PQClaimProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_providers()

    def test_native_mlkem_positive(self):
        row = trial("native_mlkem", 0)
        self.assertTrue(row["matched_session"])
        self.assertTrue(row["observed_mlkem_session"])

    def test_classical_ecdh(self):
        for case in ("forced_classical_ecdh", "provider_missing_ecdh"):
            with self.subTest(case=case):
                row = trial(case, 0)
                self.assertTrue(row["matched_session"])
                self.assertEqual(row["client_mode"], "ECDH")
                self.assertFalse(row["observed_mlkem_session"])

    def test_psk_fallback_not_pqc(self):
        for case in ("forced_classical_psk", "provider_missing_psk", "malformed_kem_psk"):
            with self.subTest(case=case):
                row = trial(case, 0)
                self.assertTrue(row["matched_session"])
                self.assertEqual(row["client_mode"], "PSK")
                self.assertFalse(row["observed_mlkem_session"])
                self.assertEqual(row["operational_posture"], "STRONG")


if __name__ == "__main__":
    unittest.main()
