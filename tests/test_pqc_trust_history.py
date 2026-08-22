import unittest
from pathlib import Path


KEYRING_H = Path("native/pqc_trust_keyring.h")
KEYRING_CPP = Path("native/pqc_trust_keyring.cpp")
TRUST_ADMIN = Path("native/pqc_trust_admin.cpp")
HISTORY_VERIFY = Path("native/pqc_history_verifier.cpp")
CMAKE = Path("CMakeLists.txt")
WORKFLOW = Path(".github/workflows/security-baseline.yml")
ENV_EXAMPLE = Path(".env.example")
DOC = Path("docs/security/v3.0.3-pqc-trust-history.md")


class PqcTrustHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = KEYRING_H.read_text(encoding="utf-8")
        cls.keyring = KEYRING_CPP.read_text(encoding="utf-8")
        cls.admin = TRUST_ADMIN.read_text(encoding="utf-8")
        cls.verifier = HISTORY_VERIFY.read_text(encoding="utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.env_example = ENV_EXAMPLE.read_text(encoding="utf-8")

    def test_keyring_has_explicit_bounded_signed_chain(self):
        self.assertIn("OMNIGUARD_PQC_TRUST_KEYRING_V1", self.header)
        self.assertIn("OMNIGUARD_PQC_TRUST_ROOT_V1", self.header)
        self.assertIn("OMNIGUARD_PQC_KEY_TRANSITION_V1", self.header)
        self.assertIn("kDefaultMaxGenerations = 8", self.header)
        self.assertIn("kAbsoluteMaxGenerations = 16", self.header)
        self.assertIn("root_self_signature_hex", self.keyring)
        self.assertIn("from_signature_hex", self.keyring)
        self.assertIn("to_signature_hex", self.keyring)
        self.assertIn("previous_transition_hash", self.keyring)
        self.assertIn("generation bound reached; refusing silent historical-key eviction", self.keyring)

    def test_keyring_binds_to_current_durable_key_and_rejects_substitution(self):
        self.assertIn("rollback/downgrade detected: active key does not match durable keystore", self.keyring)
        self.assertIn("trusted->signature_public_key != embedded_signature_public_key", self.keyring)
        self.assertIn("trusted->kem_public_key != embedded_kem_public_key", self.keyring)
        self.assertIn("historical public key was trusted", self.admin)
        self.assertIn("rolled-back PQC trust keyring was accepted", self.admin)

    def test_trust_admission_is_local_explicit_and_not_remote(self):
        self.assertIn("smartcar_pqc_trust_admin admit", self.admin)
        self.assertIn('"ADMIT:" + current.key_id', self.admin)
        self.assertIn("--previous-keystore", self.admin)
        self.assertIn("PQC trust admission reason must contain 8 to 256 characters", self.admin)
        self.assertIn('"remote_admission", false', self.admin)
        self.assertNotIn("http://", self.admin)
        self.assertNotIn("https://", self.admin)
        self.assertNotIn("socket", self.admin.lower())

    def test_historical_verifier_checks_full_ledger_authenticity(self):
        self.assertIn("OMNIGUARD_NATIVE_BLOCK_V3_2", self.verifier)
        self.assertIn("OMNIGUARD_CPP_DATA_KEY_V1", self.verifier)
        self.assertIn("OMNIGUARD_NATIVE_PQC_V1", self.verifier)
        self.assertIn("AES-GCM authentication failed", self.verifier)
        self.assertIn("telemetry/event digest validation failed", self.verifier)
        self.assertIn("block hash validation failed", self.verifier)
        self.assertIn("index/vehicle/linkage validation failed", self.verifier)
        self.assertIn("ML-DSA signature is not admitted by the verified trust keyring", self.verifier)
        self.assertIn("current-generation historical ledger ML-KEM claim failed verification", self.verifier)

    def test_historical_kem_claim_boundary_is_truthful(self):
        self.assertIn('"historical_ml_kem_decapsulation_verified", false', self.verifier)
        self.assertIn('"historical_kem_private_keys_retained", false', self.verifier)
        self.assertIn('"historical_ml_dsa_authenticity_verified", true', self.verifier)
        self.assertNotIn("historical_ml_kem_decapsulation_verified\", true", self.verifier)

    def test_build_graph_has_explicit_opt_in_targets(self):
        self.assertIn("SMARTCAR_BUILD_PQC_TRUST_ADMIN", self.cmake)
        self.assertIn("SMARTCAR_BUILD_PQC_HISTORY_VERIFY", self.cmake)
        self.assertIn("smartcar_pqc_trust_admin", self.cmake)
        self.assertIn("smartcar_pqc_history_verify", self.cmake)
        self.assertIn("native/pqc_trust_keyring.cpp", self.cmake)

    def test_configuration_and_docs_are_required(self):
        self.assertIn("SMARTCAR_CPP_PQC_TRUST_KEYRING_PATH", self.env_example)
        self.assertIn("SMARTCAR_CPP_PQC_TRUST_MAX_GENERATIONS", self.env_example)
        self.assertTrue(DOC.exists())

    def test_ci_runs_real_mixed_generation_trust_flow(self):
        self.assertIn("tests.test_pqc_trust_history", self.workflow)
        self.assertIn("Run mixed-generation native runtime validation", self.workflow)
        self.assertIn("smartcar_pqc_trust_admin init", self.workflow)
        self.assertIn("smartcar_pqc_key_admin rotate", self.workflow)
        self.assertIn("smartcar_pqc_trust_admin admit", self.workflow)
        self.assertIn("smartcar_blockchain verify", self.workflow)
        self.assertIn("smartcar_blockchain append", self.workflow)
        self.assertIn("MIXED_GENERATION_VERIFIED", self.workflow)
        self.assertIn("historical_ml_kem_decapsulation_verified", self.workflow)
        self.assertIn("historical_kem_claim_is_authoritative", self.workflow)


if __name__ == "__main__":
    unittest.main()
