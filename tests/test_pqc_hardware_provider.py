import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


class PqcHardwareProviderContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = Path("native/pqc_provider_policy.h").read_text(encoding="utf-8")
        cls.contract = Path("native/pqc_hardware_provider.h").read_text(encoding="utf-8")

    def test_unimplemented_hardware_names_do_not_claim_hardware_capabilities(self):
        self.assertIn("is_hardware_pqc_provider_name", self.policy)
        self.assertIn("runtime_probe_verified", self.policy)
        self.assertIn("every positive hardware capability stays false", self.policy)
        self.assertNotIn("return {provider, true, true, false, false, false};", self.policy)

    def test_contract_requires_non_exportable_ml_dsa_and_ml_kem_operations(self):
        for required in (
            "private_keys_non_exportable",
            "ml_dsa_44_key_generation",
            "ml_dsa_44_sign",
            "ml_kem_512_key_generation",
            "ml_kem_512_decapsulate",
            "rotation_supported",
            "device_identity",
            "evidence_reference",
            "sign_ml_dsa_44",
            "decapsulate_ml_kem_512",
        ):
            self.assertIn(required, self.contract)

    def test_private_key_export_is_not_part_of_hardware_contract(self):
        self.assertNotIn("signature_secret_key", self.contract)
        self.assertNotIn("kem_secret_key", self.contract)
        self.assertNotIn("export_private", self.contract)
        self.assertIn("Private key", self.contract)
        self.assertIn("must never be returned", self.contract)

    def test_unavailable_adapter_is_fail_closed(self):
        self.assertIn("UnavailablePqcHardwareProvider", self.contract)
        self.assertIn("software fallback is prohibited", self.contract)
        self.assertIn("validate_hardware_probe(probe)", self.contract)

    def test_header_contract_compiles_and_rejects_unverified_adapter(self):
        compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
        if compiler is None:
            self.skipTest("no C++ compiler available")

        source = textwrap.dedent(
            r'''
            #include "pqc_hardware_provider.h"
            #include <stdexcept>

            int main() {
                omniguard::UnavailablePqcHardwareProvider provider("pkcs11");
                try {
                    (void)provider.verified_capabilities();
                } catch (const std::runtime_error&) {
                    return 0;
                }
                return 1;
            }
            '''
        )
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            source_path = directory_path / "probe.cpp"
            binary_path = directory_path / "probe"
            source_path.write_text(source, encoding="utf-8")
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-I",
                    "native",
                    str(source_path),
                    "-o",
                    str(binary_path),
                ],
                check=True,
            )
            completed = subprocess.run([str(binary_path)], check=False)
            self.assertEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
