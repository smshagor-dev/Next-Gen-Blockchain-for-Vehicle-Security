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
        cls.active_operations = Path("native/pqc_active_operations.h").read_text(encoding="utf-8")
        cls.software_operations = Path("native/pqc_software_active_operations.h").read_text(encoding="utf-8")
        cls.key_material = Path("native/pqc_key_material.h").read_text(encoding="utf-8")
        cls.sensitive_bytes = Path("native/pqc_sensitive_bytes.h").read_text(encoding="utf-8")
        cls.commitment = Path("native/pqc_kem_commitment.h").read_text(encoding="utf-8")
        cls.pkcs11_provider = Path("native/pqc_pkcs11_provider.cpp").read_text(encoding="utf-8")
        cls.provider_factory = Path("native/pqc_runtime_provider_factory.h").read_text(encoding="utf-8")
        cls.cmake = Path("CMakeLists.txt").read_text(encoding="utf-8")

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
            "ml_kem_512_derived_secret_non_exportable",
            "ml_kem_512_sha3_256_raw_commitment",
            "rotation_supported",
            "device_identity",
            "evidence_reference",
            "ml_dsa_44_signature_max_size",
            "ml_kem_512_ciphertext_size",
            "ml_kem_512_shared_secret_size",
            "sign_ml_dsa_44",
            "decapsulate_ml_kem_512_commitment",
            "decapsulate_ml_kem_512",
        ):
            self.assertIn(required, self.contract)

    def test_hardware_activation_uses_two_phase_probe_and_key_evidence(self):
        self.assertIn("validate_hardware_backend_probe", self.contract)
        self.assertIn("const PqcHardwareProbe preflight = provider_->probe();", self.active_operations)
        self.assertIn("validate_hardware_backend_probe(preflight)", self.active_operations)
        self.assertIn("provider_->load_or_create_public(identity)", self.active_operations)
        self.assertIn("const PqcHardwareProbe probe = provider_->probe();", self.active_operations)
        self.assertIn("capabilities_from_verified_hardware_probe(probe)", self.active_operations)
        self.assertIn("hardware PQC provider binding changed during key provisioning", self.active_operations)
        self.assertLess(
            self.active_operations.index("validate_hardware_backend_probe(preflight)"),
            self.active_operations.index("provider_->load_or_create_public(identity)"),
        )
        self.assertLess(
            self.active_operations.index("provider_->load_or_create_public(identity)"),
            self.active_operations.index("capabilities_from_verified_hardware_probe(probe)"),
        )

    def test_commitment_schemes_are_explicit_and_versioned(self):
        self.assertIn("kKemCommitmentLegacyV1", self.commitment)
        self.assertIn("OMNIGUARD_ML_KEM_SHARED_SECRET_COMMITMENT_V1_SHA3_256_HEX", self.commitment)
        self.assertIn("kKemCommitmentRawV2", self.commitment)
        self.assertIn("OMNIGUARD_ML_KEM_SHARED_SECRET_COMMITMENT_V2_SHA3_256_RAW", self.commitment)
        self.assertIn("make_kem_commitment", self.commitment)
        self.assertIn("validate_kem_commitment", self.commitment)
        self.assertIn("encode_secret_as_hex", self.commitment)
        self.assertIn("EVP_sha3_256", self.commitment)

    def test_private_key_export_is_not_part_of_hardware_contract(self):
        self.assertNotIn("signature_secret_key", self.contract)
        self.assertNotIn("kem_secret_key", self.contract)
        self.assertNotIn("export_private", self.contract)
        self.assertIn("Private key", self.contract)
        self.assertIn("must never be returned", self.contract)
        self.assertIn("without exporting", self.contract)

    def test_active_operation_boundary_contains_no_private_key_bytes(self):
        for required in (
            "PqcActivePublicState",
            "PqcActivePrivateOperations",
            "HardwarePqcActivePrivateOperations",
            "validate_active_public_state",
            "capabilities_from_verified_hardware_probe",
            "validate_hardware_public_material",
            "verify_live_provider_binding",
            "hardware PQC provider binding changed after activation",
            "sign_ml_dsa_44",
            "decapsulate_ml_kem_512_commitment",
            "decapsulate_ml_kem_512",
            "hardware ML-KEM commitment operation requires the V2 raw-secret commitment scheme",
            "hardware ML-KEM provider returned an unexpected commitment scheme",
        ):
            self.assertIn(required, self.active_operations)
        self.assertNotIn("signature_secret_key", self.active_operations)
        self.assertNotIn("kem_secret_key", self.active_operations)
        self.assertNotIn("export_private", self.active_operations)
        self.assertIn("software PQC active state cannot claim hardware-backed/non-exportable protection", self.active_operations)

    def test_software_provider_implements_same_private_operation_contract(self):
        for required in (
            "class SoftwarePqcActivePrivateOperations final : public PqcActivePrivateOperations",
            "OQS_SIG_sign",
            "OQS_KEM_decaps",
            "PqcSensitiveBytes signature_secret_key_",
            "PqcSensitiveBytes kem_secret_key_",
            "kSoftwarePqcProvider",
            "false,",
            "true,",
        ):
            self.assertIn(required, self.software_operations)
        self.assertIn("make_kem_commitment", self.active_operations)
        self.assertIn("struct PqcKeyMaterial", self.key_material)
        self.assertIn("signature_secret_key", self.key_material)
        self.assertIn("kem_secret_key", self.key_material)
        self.assertNotIn("hardware_backed", self.key_material)

    def test_derived_shared_secret_is_move_only_zeroized_and_read_only(self):
        self.assertIn("class PqcSensitiveBytes", self.sensitive_bytes)
        self.assertIn("PqcSensitiveBytes(const PqcSensitiveBytes&) = delete", self.sensitive_bytes)
        self.assertIn("operator=(const PqcSensitiveBytes&) = delete", self.sensitive_bytes)
        self.assertIn("secure_zero_bytes", self.sensitive_bytes)
        self.assertIn("~PqcSensitiveBytes()", self.sensitive_bytes)
        self.assertIn("const unsigned char* data() const noexcept", self.sensitive_bytes)
        self.assertNotIn("\n    unsigned char* data() noexcept", self.sensitive_bytes)
        self.assertIn("PqcSensitiveBytes decapsulate_ml_kem_512", self.contract)
        self.assertIn("PqcSensitiveBytes decapsulate_ml_kem_512", self.software_operations)
        self.assertIn("PqcKemCommitment decapsulate_ml_kem_512_commitment", self.contract)
        self.assertIn("PqcKemCommitment decapsulate_ml_kem_512_commitment", self.active_operations)

    def test_pkcs11_provider_is_opt_in_and_never_static_capability_evidence(self):
        self.assertIn("SMARTCAR_ENABLE_PKCS11_PROVIDER", self.cmake)
        self.assertIn('option(SMARTCAR_ENABLE_PKCS11_PROVIDER', self.cmake)
        self.assertIn("native/pqc_pkcs11_provider.cpp", self.cmake)
        self.assertIn("SMARTCAR_ENABLE_PKCS11_PROVIDER=1", self.cmake)
        self.assertIn("#if defined(SMARTCAR_ENABLE_PKCS11_PROVIDER)", self.provider_factory)
        self.assertIn("make_pkcs11_hardware_provider_from_env", self.provider_factory)
        self.assertIn("UnavailablePqcHardwareProvider", self.provider_factory)
        self.assertIn("every positive hardware capability stays false", self.policy)

    def test_pkcs11_provider_requires_v32_interface_and_real_hardware_slot(self):
        for required in (
            "C_GetInterface(PKCS 11 v3.2)",
            "functions_->version.major != 3",
            "functions_->version.minor < 2",
            "CKF_HW_SLOT",
            "C_EncapsulateKey",
            "C_DecapsulateKey",
            "C_DigestKey",
            "CKM_ML_DSA_KEY_PAIR_GEN",
            "CKM_ML_DSA",
            "CKM_ML_KEM_KEY_PAIR_GEN",
            "CKM_ML_KEM",
            "CKM_SHA3_256",
            "CKF_GENERATE_KEY_PAIR",
            "CKF_SIGN",
            "CKF_ENCAPSULATE",
            "CKF_DECAPSULATE",
            "CKF_DIGEST",
        ):
            self.assertIn(required, self.pkcs11_provider)
        self.assertIn("hardware_slot_ && required_mechanisms_", self.pkcs11_provider)
        self.assertIn("hw_slot=", self.pkcs11_provider)

    def test_pkcs11_private_and_derived_keys_are_non_exportable(self):
        for required in (
            "CKA_SENSITIVE",
            "CKA_EXTRACTABLE",
            "CKA_ALWAYS_SENSITIVE",
            "CKA_NEVER_EXTRACTABLE",
            "verify_private_key_policy",
            "verify_derived_secret_policy",
            "private_keys_verified_",
            "derived_secret_verified_",
        ):
            self.assertIn(required, self.pkcs11_provider)
        self.assertIn("CKA_EXTRACTABLE) != CK_FALSE", self.pkcs11_provider)
        self.assertNotIn("get_attribute_bytes(handles.signature_private, CKA_VALUE)", self.pkcs11_provider)
        self.assertNotIn("get_attribute_bytes(handles.kem_private, CKA_VALUE)", self.pkcs11_provider)
        self.assertNotIn("decapsulate_ml_kem_512(\n", self.pkcs11_provider)

    def test_pkcs11_operational_proofs_bind_real_key_pairs_without_secret_export(self):
        for required in (
            "prove_signature_pair",
            "C_Verify(ML-DSA-44 pair proof)",
            "prove_kem_commitment_path",
            "C_EncapsulateKey(ML-KEM-512 proof)",
            "C_DecapsulateKey(ML-KEM-512)",
            "digest_key_with_prefix",
            "C_DigestKey(derived secret)",
            "CRYPTO_memcmp",
            "kKemCommitmentRawV2",
        ):
            self.assertIn(required, self.pkcs11_provider)
        self.assertIn("C_DestroyObject(sender proof secret)", self.pkcs11_provider)
        self.assertIn("C_DestroyObject(receiver proof secret)", self.pkcs11_provider)

    def test_pkcs11_generation_selection_is_monotonic_and_refuses_incomplete_latest_state(self):
        for required in (
            "discover_generations",
            "*generations.rbegin()",
            "latest OmniGuard generation is incomplete; refusing rollback to an older generation",
            "active_generation_ + 1",
            "kMaxGeneration",
        ):
            self.assertIn(required, self.pkcs11_provider)
        self.assertNotIn("software_encrypted_file", self.pkcs11_provider)

    def test_pkcs11_pin_input_is_explicit_and_not_persisted_by_provider(self):
        self.assertIn("SMARTCAR_CPP_PKCS11_PIN", self.pkcs11_provider)
        self.assertIn("SMARTCAR_CPP_PKCS11_PIN_FILE", self.pkcs11_provider)
        self.assertIn("regular non-symlink file", self.pkcs11_provider)
        self.assertIn("OPENSSL_cleanse(pin_.data(), pin_.size())", self.pkcs11_provider)
        self.assertNotIn("std::cout", self.pkcs11_provider)
        self.assertNotIn("std::cerr", self.pkcs11_provider)

    def test_unavailable_adapter_is_fail_closed(self):
        self.assertIn("UnavailablePqcHardwareProvider", self.contract)
        self.assertIn("software fallback is prohibited", self.contract)
        self.assertIn("validate_hardware_probe(probe)", self.contract)
        self.assertIn("decapsulate_ml_kem_512_commitment", self.contract)
        self.assertIn("fail();", self.contract)

    def test_header_contract_compiles_and_rejects_unverified_adapter(self):
        compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
        if compiler is None:
            self.skipTest("no C++ compiler available")

        source = textwrap.dedent(
            r'''
            #include "pqc_active_operations.h"
            #include <memory>
            #include <stdexcept>

            int main() {
                auto provider = std::make_shared<omniguard::UnavailablePqcHardwareProvider>("pkcs11");
                try {
                    omniguard::HardwarePqcActivePrivateOperations operations(provider, "vehicle-contract-test");
                    (void)operations.public_state();
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
                    "-Werror",
                    "-I",
                    "native",
                    str(source_path),
                    "-o",
                    str(binary_path),
                    "-lcrypto",
                ],
                check=True,
            )
            completed = subprocess.run([str(binary_path)], check=False)
            self.assertEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
