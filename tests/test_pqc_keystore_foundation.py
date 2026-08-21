import unittest
from pathlib import Path

from credential_policy import secret_policy, validate_secret_separation


HEADER = Path("native/pqc_key_store.h")
SOURCE = Path("native/pqc_key_store.cpp")
SELFTEST = Path("native/pqc_key_store_selftest.cpp")
CMAKE = Path("CMakeLists.txt")
ENV_EXAMPLE = Path(".env.example")


class PqcKeyStoreFoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.selftest = SELFTEST.read_text(encoding="utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")
        cls.env_example = ENV_EXAMPLE.read_text(encoding="utf-8")

    def test_keystore_format_and_algorithms_are_explicit(self):
        self.assertIn("OMNIGUARD_PQC_KEYSTORE_V1", self.header)
        self.assertIn('kProvider = "software_encrypted_file"', self.header)
        self.assertIn('kSignatureAlgorithm = "ML-DSA-44"', self.header)
        self.assertIn('kKemAlgorithm = "ML-KEM-512"', self.header)
        self.assertIn("OQS_SIG_alg_ml_dsa_44", self.source)
        self.assertIn("OQS_KEM_alg_ml_kem_512", self.source)

    def test_private_material_is_aes_gcm_wrapped_and_aad_bound(self):
        self.assertIn("EVP_aes_256_gcm()", self.source)
        self.assertIn("EVP_CTRL_GCM_GET_TAG", self.source)
        self.assertIn("EVP_CTRL_GCM_SET_TAG", self.source)
        self.assertIn("OMNIGUARD_CPP_PQC_KEYSTORE_KEY_V1", self.source)
        self.assertIn("OMNIGUARD_PQC_KEY_ID_V1", self.source)
        self.assertIn("native_pqc_private_material", self.source)
        self.assertIn("private_aad", self.source)

    def test_keystore_is_fail_closed_and_atomic(self):
        self.assertIn("PQC keystore symlinks are not allowed", self.source)
        self.assertIn("keystore schema contains missing or unexpected fields", self.source)
        self.assertIn("refusing to overwrite existing PQC keystore", self.source)
        self.assertIn("could not atomically publish PQC keystore", self.source)
        self.assertIn("owner_read", self.source)
        self.assertIn("owner_write", self.source)
        self.assertIn("PQC keystore authentication failed", self.source)
        self.assertIn("PQC keystore key identifier mismatch", self.source)

    def test_key_pairs_are_cryptographically_consistency_checked(self):
        self.assertIn("OQS_SIG_sign", self.source)
        self.assertIn("OQS_SIG_verify", self.source)
        self.assertIn("OQS_KEM_encaps", self.source)
        self.assertIn("OQS_KEM_decaps", self.source)
        self.assertIn("constant_time_equal", self.source)
        self.assertIn("OPENSSL_cleanse", self.source)

    def test_provider_metadata_does_not_claim_hardware_security(self):
        self.assertIn("bool hardware_backed = false", self.header)
        self.assertIn("bool non_exportable = false", self.header)
        self.assertIn("software_encrypted_file", self.selftest)
        self.assertIn("metadata.hardware_backed", self.selftest)
        self.assertIn("metadata.non_exportable", self.selftest)

    def test_selftest_covers_persistence_tamper_wrong_key_and_truncation(self):
        self.assertIn("PQC identity changed across keystore reload", self.selftest)
        self.assertIn("tampered PQC keystore was accepted", self.selftest)
        self.assertIn("PQC keystore opened with the wrong wrapping key", self.selftest)
        self.assertIn("truncated PQC keystore was silently regenerated", self.selftest)
        self.assertIn("restored keystore did not recover the original identity", self.selftest)

    def test_build_graph_compiles_keystore_with_hardened_target(self):
        self.assertIn("native/pqc_key_store.cpp", self.cmake)
        self.assertIn("SMARTCAR_BUILD_PQC_KEYSTORE_SELFTEST", self.cmake)
        self.assertIn("smartcar_pqc_keystore_selftest", self.cmake)
        self.assertIn("OpenSSL::Crypto", self.cmake)
        self.assertIn("${SMARTCAR_LIBOQS_TARGET}", self.cmake)

    def test_keystore_wrapping_key_is_an_independent_credential_domain(self):
        policy = secret_policy("SMARTCAR_CPP_PQC_KEYSTORE_KEY")
        self.assertIsNotNone(policy)
        self.assertEqual(policy.domain, "native_cpp_pqc_keystore")
        shared = "K" * 48
        env = {
            "SMARTCAR_CPP_PQC_KEYSTORE_KEY": shared,
            "SMARTCAR_CPP_DATA_KEY": shared,
        }
        with self.assertRaises(RuntimeError):
            validate_secret_separation("SMARTCAR_CPP_PQC_KEYSTORE_KEY", shared, env)
        self.assertEqual(self.env_example.count("SMARTCAR_CPP_PQC_KEYSTORE_KEY="), 1)
        self.assertIn("SMARTCAR_CPP_PQC_KEYSTORE_PATH=", self.env_example)


if __name__ == "__main__":
    unittest.main()
