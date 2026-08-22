import unittest
from pathlib import Path

from consensus_security import consensus_security_metadata


class ConsensusSecurityTests(unittest.TestCase):
    def test_permissioned_quorum_still_does_not_claim_majority_resistance(self):
        metadata = consensus_security_metadata()
        self.assertEqual(metadata["consensus_model"], "permissioned_quorum")
        self.assertTrue(metadata["validator_membership_enforced"])
        self.assertTrue(metadata["vote_signature_required"])
        self.assertTrue(metadata["duplicate_vote_rejected"])
        self.assertEqual(metadata["quorum_basis"], "configured_validator_set")
        self.assertFalse(metadata["majority_attack_resistant"])
        self.assertFalse(metadata["protects_against_forward_majority_control"])
        self.assertTrue(metadata["dual_hash_chaining"])
        self.assertTrue(metadata["retroactive_tamper_evidence"])
        self.assertFalse(metadata["secret_values_exposed"])

    @staticmethod
    def _claim_targets():
        return [
            Path("readme.md"),
            Path("docs/consensus-threat-model.md"),
            Path("native/secure_blockchain_v303.cpp"),
            Path("api/go/main.go"),
            Path("dashboard.py"),
            Path("consensus_security.py"),
        ]

    def test_no_51_percent_probability_2_pow_512_claim(self):
        for target in self._claim_targets():
            self.assertTrue(target.exists(), str(target))
            text = target.read_text(encoding="utf-8").lower()
            self.assertNotIn("2^-512", text, str(target))
            self.assertNotIn("2^−512", text, str(target))

    def test_no_dual_hash_prevents_51_percent_claim(self):
        forbidden = [
            "dual hashing prevents 51",
            "dual hash prevents 51",
            "dual-hash prevents 51",
            "51% attack requires",
            "majority adversary cannot append fraudulent",
        ]
        for target in self._claim_targets():
            self.assertTrue(target.exists(), str(target))
            text = target.read_text(encoding="utf-8").lower()
            for phrase in forbidden:
                self.assertNotIn(phrase, text, f"{target}: {phrase}")

    def test_dashboard_does_not_show_51_attack_resistant(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertNotIn("51% Attack Resistant", text)

    def test_consensus_threat_model_doc_exists(self):
        doc = Path("docs/consensus-threat-model.md")
        self.assertTrue(doc.exists())
        text = doc.read_text(encoding="utf-8")
        self.assertIn("Why a 51% Attacker Does Not Need a Hash Collision", text)
        self.assertIn("Forward Consensus Capture", text)


if __name__ == "__main__":
    unittest.main()
