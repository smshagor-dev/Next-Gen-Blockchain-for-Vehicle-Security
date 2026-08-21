import unittest
from pathlib import Path


ADMIN = Path("native/pqc_key_admin.cpp")
POLICY = Path("native/pqc_provider_policy.h")
CMAKE = Path("CMakeLists.txt")
WORKFLOW = Path(".github/workflows/security-baseline.yml")
ENV_EXAMPLE = Path(".env.example")


class PqcKeyRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = ADMIN.read_text(encoding="utf-8")
        cls.policy = POLICY.read_text(encoding="utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.env_example = ENV_EXAMPLE.read_text(encoding="utf-8")

    def test_rotation_is_explicit_local_operator_action(self):
        self.assertIn("SMARTCAR_CPP_PQC_ROTATION_ENABLED", self.admin)
        self.assertIn('"ROTATE:" + previous.key_id', self.admin)
        self.assertIn("PQC rotation reason must contain 8 to 256 characters", self.admin)
        self.assertIn('"remote_rotation", false', self.admin)
        self.assertNotIn("http://", self.admin)
        self.assertNotIn("https://", self.admin)
        self.assertNotIn("socket", self.admin.lower())

    def test_rotation_stages_and_verifies_before_activation(self):
        generation = self.admin.index("staging_store.load_or_create")
        inspect = self.admin.index("staging_store.inspect")
        replace = self.admin.index("atomic_replace_file(staging_path, active_path)")
        verify = self.admin.index("verified_store.inspect")
        self.assertLess(generation, inspect)
        self.assertLess(inspect, replace)
        self.assertLess(replace, verify)
        self.assertIn("MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH", self.admin)

    def test_rotation_preserves_encrypted_previous_identity_and_evidence(self):
        self.assertIn("copy_file(active_path, backup_path", self.admin)
        self.assertIn("OMNIGUARD_PQC_ROTATION_PREPARED_V1", self.admin)
        self.assertIn("OMNIGUARD_PQC_ROTATION_COMPLETED_V1", self.admin)
        self.assertIn("prepared_receipt_sha3_256", self.admin)
        self.assertIn("private_key_material_exposed", self.admin)
        self.assertIn("set_private_permissions(backup_path)", self.admin)
        self.assertNotIn("signature_secret_key_hex", self.admin)
        self.assertNotIn("kem_secret_key_hex", self.admin)

    def test_hardware_required_mode_fails_closed_for_software_provider(self):
        self.assertIn("SMARTCAR_CPP_PQC_HARDWARE_REQUIRED", self.policy)
        self.assertIn("hardware-backed PQC provider is required", self.policy)
        self.assertIn("TPM2/PKCS#11/HSM fallback is not simulated", self.policy)
        self.assertIn("bool hardware_backed = false", self.policy)
        self.assertIn("bool non_exportable = false", self.policy)

    def test_selftest_covers_rotation_backup_confirmation_and_policy(self):
        self.assertIn("wrong rotation confirmation changed active PQC identity", self.admin)
        self.assertIn("encrypted PQC rotation backup does not contain previous identity", self.admin)
        self.assertIn("disabled rotation changed active PQC identity", self.admin)
        self.assertIn("software PQC provider satisfied hardware-required policy", self.admin)
        self.assertIn("[PQC-KEY-ADMIN-SELF-TEST] PASS", self.admin)

    def test_build_and_ci_validation_are_required(self):
        self.assertIn("SMARTCAR_BUILD_PQC_KEY_ADMIN", self.cmake)
        self.assertIn("smartcar_pqc_key_admin", self.cmake)
        self.assertIn("tests.test_pqc_key_rotation", self.workflow)
        self.assertIn("Run guarded PQC key administration self-test", self.workflow)
        self.assertIn("SMARTCAR_CPP_PQC_HARDWARE_REQUIRED=1", self.workflow)

    def test_configuration_defaults_are_conservative(self):
        self.assertIn("SMARTCAR_CPP_PQC_ROTATION_ENABLED=0", self.env_example)
        self.assertIn("SMARTCAR_CPP_PQC_HARDWARE_REQUIRED=0", self.env_example)
        self.assertIn("SMARTCAR_CPP_PQC_ROTATION_DIR=", self.env_example)


if __name__ == "__main__":
    unittest.main()
