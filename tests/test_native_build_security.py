import re
import unittest
from pathlib import Path

from credential_policy import secret_policy, validate_secret_separation


CMAKE = Path("CMakeLists.txt")
LEGACY_CPP = Path("blockchain.cpp")
SECURE_CPP = Path("native/secure_blockchain_v303.cpp")
ENV_EXAMPLE = Path(".env.example")


class NativeBuildSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmake = CMAKE.read_text(encoding="utf-8")
        cls.secure_cpp = SECURE_CPP.read_text(encoding="utf-8")
        cls.env_example = ENV_EXAMPLE.read_text(encoding="utf-8")

    def test_native_cpu_optimization_is_opt_in(self):
        self.assertRegex(self.cmake, r'option\(SMARTCAR_ENABLE_NATIVE_OPT\s+"[^"]+"\s+OFF\)')
        self.assertIn("if(SMARTCAR_ENABLE_NATIVE_OPT)", self.cmake)
        self.assertIn("-march=native", self.cmake)

    def test_fast_math_is_explicit_lab_opt_in(self):
        self.assertRegex(self.cmake, r'option\(SMARTCAR_ENABLE_UNSAFE_FAST_MATH\s+"[^"]+"\s+OFF\)')
        self.assertIn("if(SMARTCAR_ENABLE_UNSAFE_FAST_MATH)", self.cmake)
        self.assertIn("-ffast-math", self.cmake)
        release_block = re.search(r"function\(smartcar_apply_release_options.*?endfunction\(\)", self.cmake, re.DOTALL)
        self.assertIsNotNone(release_block)
        self.assertIn("$<$<CONFIG:Release>:-O2>", release_block.group(0))

    def test_fetched_json_archive_is_checksum_pinned(self):
        self.assertIn(
            "URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d",
            self.cmake,
        )

    def test_liboqs_release_is_pinned_to_full_commit(self):
        self.assertIn('set(SMARTCAR_LIBOQS_VERSION "0.16.0")', self.cmake)
        self.assertIn('set(SMARTCAR_LIBOQS_COMMIT "5a1a854b0dc9f2141bdc771c555ee60c37950183")', self.cmake)
        self.assertIn("GIT_TAG ${SMARTCAR_LIBOQS_COMMIT}", self.cmake)
        self.assertIn('set(OQS_MINIMAL_BUILD "KEM_ml_kem_512;SIG_ml_dsa_44"', self.cmake)

    def test_hardened_target_compiles_v303_runtime_and_trust_state(self):
        target = re.search(r"add_executable\(\s*smartcar_blockchain\s+(.*?)\)", self.cmake, re.DOTALL)
        self.assertIsNotNone(target)
        sources = target.group(1)
        self.assertIn("native/secure_blockchain_v303.cpp", sources)
        self.assertIn("native/pqc_key_store.cpp", sources)
        self.assertIn("native/pqc_trust_keyring.cpp", sources)
        self.assertIn("native/pqc_state_guard.cpp", sources)
        self.assertNotIn("native/secure_blockchain.cpp", sources)
        self.assertNotRegex(sources, r"(^|\s)blockchain\.cpp($|\s)")
        self.assertIn("OpenSSL::Crypto", self.cmake)

    def test_legacy_simulated_pqc_build_path_is_removed(self):
        self.assertFalse(LEGACY_CPP.exists())
        self.assertNotIn("SMARTCAR_BUILD_LEGACY_CPP_DEMO", self.cmake)
        self.assertNotIn("SMARTCAR_ALLOW_SIMULATED_PQC_BUILD", self.cmake)
        self.assertNotIn("smartcar_blockchain_legacy_demo", self.cmake)
        self.assertNotIn("SIM_PQC", self.secure_cpp)
        self.assertNotIn("SIMULATED", self.secure_cpp)

    def test_missing_real_liboqs_fails_closed_for_hardened_target(self):
        self.assertRegex(self.cmake, r'option\(SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS\s+"[^"]+"\s+OFF\)')
        self.assertIn("smartcar_require_real_pqc", self.cmake)
        self.assertIn("Simulated PQC is not available in the supported v3.0.3 build graph", self.cmake)

    def test_secure_source_uses_authenticated_encryption(self):
        self.assertIn("EVP_aes_256_gcm()", self.secure_cpp)
        self.assertIn("EVP_CTRL_GCM_GET_TAG", self.secure_cpp)
        self.assertIn("EVP_CTRL_GCM_SET_TAG", self.secure_cpp)
        self.assertIn("RAND_bytes", self.secure_cpp)
        self.assertIn("dual_hash_encrypted", self.secure_cpp)
        self.assertIn("OMNIGUARD_DUAL_HASH_AAD_V1", self.secure_cpp)

    def test_secure_source_uses_standardized_pqc_only(self):
        self.assertIn("OQS_SIG_alg_ml_dsa_44", self.secure_cpp)
        self.assertIn("OQS_KEM_alg_ml_kem_512", self.secure_cpp)
        self.assertIn("ML-DSA-44+ML-KEM-512", self.secure_cpp)
        self.assertNotIn("Dilithium2", self.secure_cpp)
        self.assertNotIn("Kyber512", self.secure_cpp)

    def test_native_runtime_integrates_historical_trust_and_rollback_anchor(self):
        self.assertIn("MIXED_GENERATION_VERIFIED", self.secure_cpp)
        self.assertIn("verify_detached_signature", self.secure_cpp)
        self.assertIn("historical_ml_kem_decapsulation_verified", self.secure_cpp)
        self.assertIn("historical_kem_claim_is_authoritative", self.secure_cpp)
        self.assertIn("SMARTCAR_CPP_PQC_ROLLBACK_ANCHOR_REQUIRED", self.secure_cpp)
        self.assertIn("PqcRollbackAnchor", self.secure_cpp)

    def test_native_secrets_are_explicit_and_not_embedded(self):
        self.assertIn('require_env_secret("SMARTCAR_CPP_DATA_KEY")', self.secure_cpp)
        self.assertIn('require_env_secret("SMARTCAR_AUTH_TOKEN")', self.secure_cpp)
        self.assertIn('require_env_secret("SMARTCAR_CPP_PQC_KEYSTORE_KEY")', self.secure_cpp)
        self.assertNotIn("SmartCarSecretKey2024", self.secure_cpp)
        self.assertNotIn("SECURE_AUTH_TOKEN_SHA3_2024", self.secure_cpp)
        self.assertEqual(self.env_example.count("SMARTCAR_CPP_DATA_KEY="), 1)

    def test_cpp_data_key_is_a_separate_credential_domain(self):
        policy = secret_policy("SMARTCAR_CPP_DATA_KEY")
        self.assertIsNotNone(policy)
        self.assertEqual(policy.domain, "native_cpp_data")
        reused = "R" * 48
        env = {"SMARTCAR_CPP_DATA_KEY": reused, "SMARTCAR_AUTH_TOKEN": reused}
        with self.assertRaises(RuntimeError):
            validate_secret_separation("SMARTCAR_CPP_DATA_KEY", reused, env)

    def test_validation_toolchain_pin_is_explicit_opt_in(self):
        self.assertRegex(self.cmake, r'option\(SMARTCAR_ENFORCE_VALIDATION_TOOLCHAIN\s+"[^"]+"\s+OFF\)')
        self.assertIn('CMAKE_CXX_COMPILER_ID STREQUAL "GNU"', self.cmake)
        self.assertIn('VERSION_LESS "13.3"', self.cmake)

    def test_ipo_is_not_default_release_behavior(self):
        self.assertRegex(self.cmake, r'option\(SMARTCAR_ENABLE_IPO\s+"[^"]+"\s+OFF\)')


if __name__ == "__main__":
    unittest.main()
