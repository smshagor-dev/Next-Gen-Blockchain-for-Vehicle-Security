import hashlib
import hmac
import os
import unittest
from unittest.mock import patch

from key_provider import EnvironmentKeyProvider, SecretBuffer, get_key_provider
from runtime_isolation import build_isolated_child_environment, subprocess_isolation_kwargs


class KeyProviderSecurityTests(unittest.TestCase):
    def test_secret_buffer_zeroizes_owned_memory(self):
        secret = SecretBuffer("A" * 40)
        self.assertIn("redacted=True", repr(secret))
        self.assertNotEqual(bytes(secret._data), b"\x00" * 40)
        secret.zeroize()
        self.assertEqual(bytes(secret._data), b"\x00" * 40)
        self.assertTrue(secret.closed)
        with self.assertRaises(RuntimeError):
            secret.text_copy()

    def test_environment_provider_hmac_matches_expected(self):
        key = "K" * 40
        env = {"SMARTCAR_GO_API_SECRET": key}
        provider = EnvironmentKeyProvider(environ=env)
        payload = b"request-payload"
        actual = provider.hmac_sha256("SMARTCAR_GO_API_SECRET", payload, purpose="unit-test")
        expected = hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()
        self.assertEqual(actual, expected)

    def test_audit_never_contains_secret_value(self):
        key = "S" * 40
        provider = EnvironmentKeyProvider(environ={"SMARTCAR_GO_API_SECRET": key})
        with provider.export_secret("SMARTCAR_GO_API_SECRET", purpose="audit-test") as handle:
            self.assertEqual(handle.text_copy(), key)
        serialized = repr(provider.audit.snapshot()) + repr(provider.metadata())
        self.assertNotIn(key, serialized)
        self.assertIn("SMARTCAR_GO_API_SECRET", serialized)

    def test_hardware_requirement_rejects_environment_provider(self):
        env = {
            "SMARTCAR_KEY_PROVIDER": "environment",
            "SMARTCAR_REQUIRE_HARDWARE_KEY_PROVIDER": "1",
        }
        with self.assertRaises(RuntimeError):
            get_key_provider(environ=env)

    def test_unavailable_hardware_provider_fails_closed(self):
        provider = get_key_provider(environ={"SMARTCAR_KEY_PROVIDER": "tpm2"})
        self.assertTrue(provider.capabilities.hardware_backed)
        self.assertFalse(provider.capabilities.exportable)
        with self.assertRaises(RuntimeError):
            provider.export_secret("SMARTCAR_GO_API_SECRET", purpose="test")

    def test_cross_domain_reuse_is_rejected(self):
        reused = "R" * 40
        env = {
            "SMARTCAR_GO_API_SECRET": reused,
            "SMARTCAR_RECOVERY_KEY": reused,
        }
        provider = EnvironmentKeyProvider(environ=env)
        with self.assertRaises(RuntimeError):
            provider.export_secret("SMARTCAR_GO_API_SECRET")


class RuntimeIsolationTests(unittest.TestCase):
    def test_child_environment_strips_unrelated_project_secrets(self):
        base = {
            "PATH": "/usr/bin",
            "HOME": "/tmp/home",
            "SMARTCAR_GO_API_SECRET": "A" * 40,
            "SMARTCAR_AUTH_TOKEN": "B" * 40,
            "SMARTCAR_VALIDATOR_KEY": "C" * 40,
        }
        child, audit = build_isolated_child_environment(
            base,
            allowed_smartcar_names={"SMARTCAR_GO_API_SECRET", "SMARTCAR_GO_DATA_DIR"},
            smartcar_overrides={"SMARTCAR_GO_API_SECRET": "D" * 40, "SMARTCAR_GO_DATA_DIR": "/tmp/data"},
        )
        self.assertEqual(child["PATH"], "/usr/bin")
        self.assertEqual(child["SMARTCAR_GO_API_SECRET"], "D" * 40)
        self.assertEqual(child["SMARTCAR_GO_DATA_DIR"], "/tmp/data")
        self.assertNotIn("SMARTCAR_AUTH_TOKEN", child)
        self.assertNotIn("SMARTCAR_VALIDATOR_KEY", child)
        self.assertGreaterEqual(audit.stripped_smartcar_count, 2)

    def test_child_environment_strips_injection_variables(self):
        base = {
            "PATH": "/usr/bin",
            "PYTHONPATH": "/attacker/python",
            "LD_PRELOAD": "/attacker/lib.so",
            "DYLD_INSERT_LIBRARIES": "/attacker/lib.dylib",
        }
        child, audit = build_isolated_child_environment(base)
        self.assertEqual(child, {"PATH": "/usr/bin"})
        self.assertEqual(audit.stripped_injection_count, 3)

    def test_unlisted_override_is_rejected(self):
        with self.assertRaises(ValueError):
            build_isolated_child_environment(
                {"PATH": "/usr/bin"},
                allowed_smartcar_names={"SMARTCAR_GO_API_SECRET"},
                smartcar_overrides={"SMARTCAR_AUTH_TOKEN": "X" * 40},
            )

    def test_subprocess_flags_close_descriptors(self):
        kwargs = subprocess_isolation_kwargs()
        self.assertTrue(kwargs.get("close_fds"))
        if os.name == "nt":
            self.assertIn("creationflags", kwargs)
        else:
            self.assertTrue(kwargs.get("start_new_session"))


if __name__ == "__main__":
    unittest.main()
