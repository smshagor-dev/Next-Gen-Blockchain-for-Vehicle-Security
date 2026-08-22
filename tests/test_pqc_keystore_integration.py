import re
import unittest
from pathlib import Path


SECURE_CPP = Path("native/secure_blockchain.cpp")
KEYSTORE_CPP = Path("native/pqc_key_store.cpp")
WORKFLOW = Path(".github/workflows/security-baseline.yml")


class PqcKeyStoreIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secure = SECURE_CPP.read_text(encoding="utf-8")
        cls.keystore = KEYSTORE_CPP.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_supported_native_core_loads_durable_key_material(self):
        self.assertIn('#include "pqc_key_store.h"', self.secure)
        self.assertIn(
            "explicit RealPqcEngine(omniguard::PqcKeyMaterial material)",
            self.secure,
        )
        self.assertIn("omniguard::PqcKeyStore(", self.secure)
        self.assertIn("pqc_keystore_path", self.secure)
        self.assertIn("pqc_keystore_key", self.secure)
        self.assertIn("vehicle_id_", self.secure)
        self.assertIn(".load_or_create()", self.secure)

    def test_supported_native_core_no_longer_generates_ephemeral_keypairs(self):
        real_engine = re.search(
            r"class RealPqcEngine \{.*?\n\};\n\nstruct TelemetryData",
            self.secure,
            re.DOTALL,
        )
        self.assertIsNotNone(real_engine)
        self.assertNotIn("OQS_SIG_keypair", real_engine.group(0))
        self.assertNotIn("OQS_KEM_keypair", real_engine.group(0))
        self.assertIn("OQS_SIG_keypair", self.keystore)
        self.assertIn("OQS_KEM_keypair", self.keystore)

    def test_durable_key_id_is_bound_into_pqc_artifacts_and_persistence(self):
        self.assertIn("std::string key_id;", self.secure)
        self.assertIn("artifact.key_id = key_id_", self.secure)
        self.assertIn("artifact.key_id != key_id_", self.secure)
        self.assertIn('{"pqc_key_id", block.pqc.key_id}', self.secure)
        self.assertIn("pqc_.key_id()", self.secure)
        self.assertIn("block.pqc.key_id", self.secure)

    def test_native_runtime_requires_keystore_configuration(self):
        self.assertIn(
            'require_env_secret("SMARTCAR_CPP_PQC_KEYSTORE_KEY")',
            self.secure,
        )
        self.assertIn(
            'require_env_value("SMARTCAR_CPP_PQC_KEYSTORE_PATH")',
            self.secure,
        )
        self.assertIn(
            "durable PQC identity is not bound to the configured vehicle identity",
            self.secure,
        )

    def test_main_native_selftest_covers_restart_and_wrong_key(self):
        self.assertIn(
            "durable PQC identity changed across native restart",
            self.secure,
        )
        self.assertIn(
            "native core accepted a wrong PQC keystore wrapping key",
            self.secure,
        )
        self.assertIn("reloaded.pqc_key_id() != first_key_id", self.secure)
        self.assertIn("wrong_key_rejected", self.secure)

    def test_hosted_ci_supplies_isolated_keystore_to_supported_native_selftest(self):
        self.assertIn("tests.test_pqc_keystore_integration", self.workflow)
        self.assertIn("Run secure native v3.0.3 self-test", self.workflow)
        self.assertIn('root="$RUNNER_TEMP/v303-native"', self.workflow)
        self.assertIn('rm -rf "$root" && mkdir -p "$root"', self.workflow)
        self.assertIn("SMARTCAR_CPP_PQC_KEYSTORE_KEY", self.workflow)
        self.assertIn('SMARTCAR_CPP_PQC_KEYSTORE_PATH="$root/identity.json"', self.workflow)
        self.assertIn("SMARTCAR_CPP_PQC_PROVIDER=software_encrypted_file", self.workflow)
        self.assertIn("SMARTCAR_CPP_PQC_HARDWARE_REQUIRED=0", self.workflow)


if __name__ == "__main__":
    unittest.main()
