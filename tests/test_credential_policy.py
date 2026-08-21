import json
import os
import unittest
from unittest.mock import patch

from credential_policy import credential_policy_metadata
from env_config import get_env, get_required_secret, get_secret_ring


class CredentialPolicyTests(unittest.TestCase):
    def test_sensitive_caller_default_is_rejected(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                get_env("SMARTCAR_VALIDATOR_KEY", "legacy-static-fallback")

    def test_lab_only_compatibility_flag_allows_sensitive_default(self):
        with patch.dict(
            os.environ,
            {"SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS": "1"},
            clear=True,
        ):
            self.assertEqual(
                get_env("SMARTCAR_VALIDATOR_KEY", "legacy-static-fallback"),
                "legacy-static-fallback",
            )

    def test_explicit_sensitive_secret_is_quality_checked(self):
        with patch.dict(
            os.environ,
            {"SMARTCAR_VALIDATOR_KEY": "too-short"},
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                get_env("SMARTCAR_VALIDATOR_KEY", "unused")

    def test_cross_domain_secret_reuse_is_rejected(self):
        shared = "S" * 48
        with patch.dict(
            os.environ,
            {
                "SMARTCAR_AUTH_TOKEN": shared,
                "SMARTCAR_RECOVERY_KEY": shared,
            },
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                get_required_secret("SMARTCAR_AUTH_TOKEN")

    def test_distinct_domains_accept_independent_secrets(self):
        auth = "A" * 48
        recovery = "R" * 48
        with patch.dict(
            os.environ,
            {
                "SMARTCAR_AUTH_TOKEN": auth,
                "SMARTCAR_RECOVERY_KEY": recovery,
            },
            clear=True,
        ):
            self.assertEqual(get_required_secret("SMARTCAR_AUTH_TOKEN"), auth)
            self.assertEqual(get_required_secret("SMARTCAR_RECOVERY_KEY"), recovery)

    def test_rotation_ring_accepts_distinct_previous_secret(self):
        current = "C" * 48
        previous = "P" * 48
        with patch.dict(
            os.environ,
            {
                "SMARTCAR_GO_API_SECRET": current,
                "SMARTCAR_GO_API_SECRET_PREVIOUS": previous,
            },
            clear=True,
        ):
            self.assertEqual(
                get_secret_ring("SMARTCAR_GO_API_SECRET"),
                (current, previous),
            )

    def test_rotation_ring_rejects_same_current_and_previous(self):
        same = "K" * 48
        with patch.dict(
            os.environ,
            {
                "SMARTCAR_GO_API_SECRET": same,
                "SMARTCAR_GO_API_SECRET_PREVIOUS": same,
            },
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                get_secret_ring("SMARTCAR_GO_API_SECRET")

    def test_registry_rejects_one_secret_for_multiple_identities(self):
        shared = "N" * 48
        registry = json.dumps({"vehicle-a": shared, "vehicle-b": shared})
        with patch.dict(
            os.environ,
            {"SMARTCAR_V2X_NODE_KEYS_JSON": registry},
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                get_env("SMARTCAR_V2X_NODE_KEYS_JSON", "{}")

    def test_registry_rejects_short_secret(self):
        registry = json.dumps({"vehicle-a": "short"})
        with patch.dict(
            os.environ,
            {"SMARTCAR_V2X_NODE_KEYS_JSON": registry},
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                get_env("SMARTCAR_V2X_NODE_KEYS_JSON", "{}")

    def test_registry_accepts_independent_credentials(self):
        registry = json.dumps(
            {
                "vehicle-a": "A" * 48,
                "vehicle-b": "B" * 48,
            }
        )
        with patch.dict(
            os.environ,
            {"SMARTCAR_V2X_NODE_KEYS_JSON": registry},
            clear=True,
        ):
            self.assertEqual(
                get_env("SMARTCAR_V2X_NODE_KEYS_JSON", "{}"),
                registry,
            )

    def test_metadata_never_exposes_secret_values(self):
        secret = "Q" * 48
        with patch.dict(
            os.environ,
            {
                "SMARTCAR_AUTH_TOKEN": secret,
                "SMARTCAR_AUTH_TOKEN_PREVIOUS": "Z" * 48,
            },
            clear=True,
        ):
            metadata = credential_policy_metadata()
            encoded = json.dumps(metadata)
            self.assertNotIn(secret, encoded)
            self.assertFalse(metadata["secret_values_exposed"])
            self.assertTrue(metadata["strict_defaults"])


if __name__ == "__main__":
    unittest.main()
