import re
import unittest
from pathlib import Path

from credential_policy import secret_policy, validate_secret_separation


CMAKE = Path("CMakeLists.txt")
LEGACY_CPP = Path("blockchain.cpp")
SECURE_CPP = Path("native/secure_blockchain.cpp")
ENV_EXAMPLE = Path(".env.example")


class NativeBuildSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmake = CMAKE.read_text(encoding="utf-8")
        cls.legacy_cpp = LEGACY_CPP.read_text(encoding="utf-8")
        cls.secure_cpp = SECURE_CPP.read_text(encoding="utf-8")
        cls.env_example = ENV_EXAMPLE.read_text(encoding="utf-8")

    def test_native_cpu_optimization_is_opt_in(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_ENABLE_NATIVE_OPT\s+"[^"]+"\s+OFF\)',
        )
        self.assertIn("if(SMARTCAR_ENABLE_NATIVE_OPT)", self.cmake)
        self.assertIn("-march=native", self.cmake)

    def test_fast_math_is_explicit_lab_opt_in(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_ENABLE_UNSAFE_FAST_MATH\s+"[^"]+"\s+OFF\)',
        )
        self.assertIn("if(SMARTCAR_ENABLE_UNSAFE_FAST_MATH)", self.cmake)
        self.assertIn("-ffast-math", self.cmake)
        release_block = re.search(
            r"function\(smartcar_apply_release_options.*?endfunction\(\)",
            self.cmake,
            re.DOTALL,
        )
        self.assertIsNotNone(release_block)
        self.assertIn("$<$<CONFIG:Release>:-O2>", release_block.group(0))

    def test_fetched_json_archive_is_checksum_pinned(self):
        self.assertIn(
            "URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d",
            self.cmake,
        )

    def test_liboqs_release_is_pinned_to_full_commit(self):
        self.assertIn('set(SMARTCAR_LIBOQS_VERSION "0.16.0")', self.cmake)
        self.assertIn(
            'set(SMARTCAR_LIBOQS_COMMIT "5a1a854b0dc9f2141bdc771c555ee60c37950183")',
            self.cmake,
        )
        self.assertIn("GIT_TAG ${SMARTCAR_LIBOQS_COMMIT}", self.cmake)
        self.assertIn('set(OQS_MINIMAL_BUILD "KEM_ml_kem_512;SIG_ml_dsa_44"', self.cmake)

    def test_hardened_target_never_compiles_legacy_source(self):
        target = re.search(
            r"add_executable\(\s*smartcar_blockchain\s+(.*?)\)",
            self.cmake,
            re.DOTALL,
        )
        self.assertIsNotNone(target)
        sources = target.group(1)
        self.assertIn("native/secure_blockchain.cpp", sources)
        self.assertIn("native/pqc_key_store.cpp", sources)
        self.assertNotRegex(sources, r"(^|\s)blockchain\.cpp($|\s)")
        self.assertNotIn("add_executable(smartcar_blockchain blockchain.cpp)", self.cmake)
        self.assertIn("OpenSSL::Crypto", self.cmake)

    def test_legacy_xor_and_simulated_pqc_are_isolated_to_opt_in_target(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_BUILD_LEGACY_CPP_DEMO\s+"[^"]+"\s+OFF\)',
        )
        self.assertIn(
            "add_executable(smartcar_blockchain_legacy_demo blockchain.cpp)",
            self.cmake,
        )
        self.assertIn("class SimpleEncrypt", self.legacy_cpp)
        self.assertIn("SIMULATED", self.legacy_cpp)
        self.assertNotIn("SimpleEncrypt", self.secure_cpp)
        self.assertNotIn("SIM_PQC", self.secure_cpp)
        self.assertNotIn("SIMULATED", self.secure_cpp)

    def test_missing_real_liboqs_fails_closed_for_hardened_target(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS\s+"[^"]+"\s+OFF\)',
        )
        self.assertIn("if(NOT SMARTCAR_LIBOQS_TARGET)", self.cmake)
        self.assertIn("Simulated PQC is not compiled into smartcar_blockchain", self.cmake)

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

    def test_native_secrets_are_explicit_and_not_embedded(self):
        self.assertIn('require_env_secret("SMARTCAR_CPP_DATA_KEY")', self.secure_cpp)
        self.assertIn('require_env_secret("SMARTCAR_AUTH_TOKEN")', self.secure_cpp)
        self.assertNotIn("SmartCarSecretKey2024", self.secure_cpp)
        self.assertNotIn("SECURE_AUTH_TOKEN_SHA3_2024", self.secure_cpp)
        self.assertEqual(self.env_example.count("SMARTCAR_CPP_DATA_KEY="), 1)

    def test_cpp_data_key_is_a_separate_credential_domain(self):
        policy = secret_policy("SMARTCAR_CPP_DATA_KEY")
        self.assertIsNotNone(policy)
        self.assertEqual(policy.domain, "native_cpp_data")
        reused = "R" * 48
        env = {
            "SMARTCAR_CPP_DATA_KEY": reused,
            "SMARTCAR_AUTH_TOKEN": reused,
        }
        with self.assertRaises(RuntimeError):
            validate_secret_separation("SMARTCAR_CPP_DATA_KEY", reused, env)

    def test_ipo_is_not_default_release_behavior(self):
        self.assertRegex(
            self.cmake,
            r'option\(SMARTCAR_ENABLE_IPO\s+"[^"]+"\s+OFF\)',
        )


if __name__ == "__main__":
    unittest.main()
