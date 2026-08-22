import json
import tempfile
import unittest
from pathlib import Path

from release_integrity import (
    MANIFEST_SCHEMA,
    RELEASE_TAG,
    build_manifest,
    current_commit,
    verify_manifest,
    write_manifest,
)
from release_metadata import RELEASE_VERSION


TEST_COMMIT = "a" * 40


class ReleaseIntegrityTests(unittest.TestCase):
    def test_manifest_is_deterministic_for_same_commit(self):
        self.assertEqual(build_manifest(commit_sha=TEST_COMMIT), build_manifest(commit_sha=TEST_COMMIT))

    def test_manifest_has_expected_release_and_security_profile(self):
        manifest = build_manifest(commit_sha=TEST_COMMIT)
        self.assertEqual(manifest["schema"], MANIFEST_SCHEMA)
        self.assertEqual(manifest["release_version"], RELEASE_VERSION)
        self.assertEqual(manifest["release_tag"], RELEASE_TAG)
        self.assertEqual(manifest["internal_hardening_phase"], "v3.3")
        self.assertFalse(manifest["secret_values_exposed"])
        self.assertFalse(manifest["claims"]["production_certified"])
        profile = manifest["native_security_profile"]
        self.assertEqual(profile["data_protection"], "AES-256-GCM")
        self.assertEqual(profile["signature"], "ML-DSA-44")
        self.assertEqual(profile["key_encapsulation"], "ML-KEM-512")
        self.assertFalse(profile["simulated_pqc_supported_target"])
        self.assertTrue(profile["legacy_simulated_pqc_source_removed"])
        self.assertTrue(profile["durable_identity"])
        self.assertTrue(profile["signed_historical_trust"])
        self.assertTrue(profile["mixed_generation_verification"])
        self.assertFalse(profile["hardware_pqc_provider_implemented"])
        self.assertFalse(profile["hardware_monotonic_rollback_protection"])

    def test_manifest_covers_version_and_secure_native_source(self):
        manifest = build_manifest(commit_sha=TEST_COMMIT)
        records = {item["path"]: item for item in manifest["source_tree"]["files"]}
        self.assertIn("VERSION", records)
        self.assertIn("CMakeLists.txt", records)
        self.assertIn("native/secure_blockchain_v303.cpp", records)
        self.assertIn("native/pqc_state_guard.cpp", records)
        self.assertNotIn("blockchain.cpp", records)
        for record in records.values():
            self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreaterEqual(record["size"], 0)

    def test_dependency_pins_are_recorded(self):
        pins = build_manifest(commit_sha=TEST_COMMIT)["dependency_pins"]
        self.assertEqual(pins["liboqs_version"], "0.16.0")
        self.assertRegex(pins["liboqs_commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(pins["nlohmann_json_version"], "3.11.3")
        self.assertRegex(pins["nlohmann_json_sha256"], r"^[0-9a-f]{64}$")

    def test_manifest_round_trip_verification_binds_current_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "manifest.json"
            write_manifest(target)
            self.assertTrue(verify_manifest(target))
            payload = json.loads(target.read_text(encoding="utf-8"))
            payload["commit_sha"] = TEST_COMMIT
            target.write_text(json.dumps(payload), encoding="utf-8")
            self.assertNotEqual(TEST_COMMIT, current_commit())
            self.assertFalse(verify_manifest(target))

    def test_manifest_rejects_content_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "manifest.json"
            write_manifest(target)
            payload = json.loads(target.read_text(encoding="utf-8"))
            payload["release_version"] = "0.0.0"
            target.write_text(json.dumps(payload), encoding="utf-8")
            self.assertFalse(verify_manifest(target))

    def test_tracked_sensitive_local_env_is_not_present(self):
        paths = {item["path"] for item in build_manifest(commit_sha=TEST_COMMIT)["source_tree"]["files"]}
        self.assertNotIn(".env", paths)
        self.assertIn(".env.example", paths)


if __name__ == "__main__":
    unittest.main()
