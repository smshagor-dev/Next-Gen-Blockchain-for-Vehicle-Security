import re
import subprocess
import unittest
from pathlib import Path

from credential_policy import secret_policy
from smart_contracts import ContractConnector


class V303FinalHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = Path("native/secure_blockchain_v303.cpp").read_text(encoding="utf-8")
        cls.provider = Path("native/pqc_provider_policy.h").read_text(encoding="utf-8")
        cls.anchor = Path("native/pqc_state_guard.cpp").read_text(encoding="utf-8")
        cls.state_admin = Path("native/pqc_state_admin.cpp").read_text(encoding="utf-8")
        cls.cmake = Path("CMakeLists.txt").read_text(encoding="utf-8")
        cls.contracts = Path("smart_contracts.py").read_text(encoding="utf-8")

    def test_runtime_load_verify_append_is_fail_closed(self):
        for required in (
            "void load(",
            "void append(",
            "read_bounded_json",
            "historical PQC generation encountered without configured trust keyring",
            "verify_detached_signature",
            "MIXED_GENERATION_VERIFIED",
            "historical_ml_kem_decapsulation_verified",
            "historical_kem_claim_is_authoritative",
        ):
            self.assertIn(required, self.runtime)
        self.assertIn("(void)verify();", self.runtime)
        self.assertIn("refusing to overwrite an existing native ledger", self.runtime)

    def test_rollback_anchor_is_authenticated_and_not_overclaimed(self):
        self.assertIn("OMNIGUARD_PQC_ROLLBACK_ANCHOR_V1", self.anchor)
        self.assertIn("HMAC", self.anchor)
        self.assertIn("sequence != generation", self.anchor)
        self.assertIn("hardware_monotonic", self.anchor)
        self.assertIn("externally_protected", self.anchor)
        self.assertIn("false", self.anchor)
        self.assertIn("advance must be exactly one new trusted generation", self.anchor)

    def test_recovery_never_silently_restores_historical_identity(self):
        self.assertIn("automatic_restore_allowed", self.state_admin)
        self.assertIn("requires_explicit_operator_recovery_procedure", self.state_admin)
        self.assertIn("rollback_anchor_must_not_be_decremented", self.state_admin)
        self.assertNotIn("copy_file(backup", self.state_admin)
        self.assertNotIn("rename(backup", self.state_admin)

    def test_hardware_provider_names_fail_closed_until_real_backend_exists(self):
        for provider in ("tpm2", "pkcs11", "hsm"):
            self.assertIn(f'"{provider}"', self.provider)
        self.assertIn("implemented = false", self.provider)
        self.assertIn("available = false", self.provider)
        self.assertIn("hardware provider fallback is never simulated", self.provider)
        self.assertIn("SMARTCAR_CPP_PQC_PROVIDER", self.provider)

    def test_rollback_key_has_independent_credential_domain(self):
        policy = secret_policy("SMARTCAR_CPP_PQC_ROLLBACK_KEY")
        self.assertIsNotNone(policy)
        self.assertEqual(policy.domain, "native_cpp_pqc_rollback")
        self.assertEqual(policy.min_length, 32)

    def test_smart_contract_mock_identifier_is_deterministic(self):
        self.assertNotIn("abs(hash(", self.contracts)
        self.assertIn("OMNIGUARD_SMART_CONTRACT_MOCK_V2", self.contracts)
        connector = ContractConnector("c", "p", "http://127.0.0.1", mock_mode=True)
        payload = {"b": 2, "a": 1}
        first = connector.invoke("m", payload)["tx_hash"]
        second = connector.invoke("m", {"a": 1, "b": 2})["tx_hash"]
        self.assertEqual(first, second)
        self.assertRegex(first, r"^mock_[0-9a-f]{64}$")

    def test_remote_contract_mode_does_not_claim_unverified_real_success(self):
        self.assertIn('"mode": "remote_rpc"', self.contracts)
        self.assertIn("REMOTE_CONTRACT_RECEIPT_UNVERIFIED", self.contracts)
        self.assertNotIn('"mode": "real"', self.contracts)

    def test_legacy_cpp_simulated_crypto_source_is_removed(self):
        self.assertFalse(Path("blockchain.cpp").exists())
        self.assertNotIn("SMARTCAR_BUILD_LEGACY_CPP_DEMO", self.cmake)
        self.assertNotIn("SMARTCAR_ALLOW_SIMULATED_PQC_BUILD", self.cmake)

    def test_supply_chain_tools_and_history_runbook_exist(self):
        for path in (
            "scripts/generate_sbom.py",
            "scripts/generate_provenance.py",
            "scripts/secret_scan.py",
            "docs/security/SUPPLY_CHAIN.md",
            "docs/security/HISTORY_REMEDIATION.md",
        ):
            self.assertTrue(Path(path).exists(), path)
        subprocess.run(["python", "-m", "py_compile", "scripts/generate_sbom.py", "scripts/generate_provenance.py", "scripts/secret_scan.py"], check=True)

    def test_release_version_is_consistently_3_0_3(self):
        self.assertEqual(Path("VERSION").read_text(encoding="utf-8").strip(), "3.0.3")
        self.assertRegex(self.cmake, r"project\(SmartCarBlockchain VERSION 3\.0\.3 LANGUAGES CXX\)")
        self.assertIn('const releaseVersion = "3.0.3"', Path("api/go/release_version.go").read_text(encoding="utf-8"))
        self.assertTrue(Path("docs/releases/v3.0.3.md").exists())
        self.assertTrue(Path("docs/releases/v3.0.3-checklist.md").exists())
        self.assertTrue(Path("scripts/create_v3_0_3_tag.sh").exists())
        self.assertTrue(Path(".github/workflows/create-v3.0.3-tag.yml").exists())


if __name__ == "__main__":
    unittest.main()
