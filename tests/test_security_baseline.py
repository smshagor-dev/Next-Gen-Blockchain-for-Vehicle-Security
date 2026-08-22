import os
import unittest
from unittest.mock import patch

from env_config import _parse_env_line, get_required_secret
from tests.test_local_env_bootstrap import LocalEnvBootstrapTests
from tests.test_runtime_backend_readiness import RuntimeBackendReadinessTests

# Keep the two imported TestCase classes in this module intentionally. Both the
# Security Baseline and guarded v3.0.3 publication workflow already execute
# tests.test_security_baseline, so unittest's module loader will include these
# recent local-bootstrap and Go-readiness regressions in the final release gate.
assert issubclass(LocalEnvBootstrapTests, unittest.TestCase)
assert issubclass(RuntimeBackendReadinessTests, unittest.TestCase)


class SecurityBaselineTests(unittest.TestCase):
    def test_unquoted_hash_inside_secret_is_preserved(self):
        self.assertEqual(
            _parse_env_line("SMARTCAR_TEST_SECRET=alpha#beta"),
            ("SMARTCAR_TEST_SECRET", "alpha#beta"),
        )

    def test_whitespace_delimited_inline_comment_is_removed(self):
        self.assertEqual(
            _parse_env_line("SMARTCAR_TEST_SECRET=alpha # local comment"),
            ("SMARTCAR_TEST_SECRET", "alpha"),
        )

    def test_quoted_hash_is_preserved(self):
        self.assertEqual(
            _parse_env_line('SMARTCAR_TEST_SECRET="alpha#beta" # local comment'),
            ("SMARTCAR_TEST_SECRET", "alpha#beta"),
        )

    def test_invalid_environment_key_is_rejected(self):
        self.assertEqual(_parse_env_line("BAD-KEY=value"), (None, None))

    def test_unterminated_quote_is_rejected(self):
        self.assertEqual(_parse_env_line('SMARTCAR_TEST_SECRET="unterminated'), (None, None))

    def test_required_secret_rejects_missing_value(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                get_required_secret("SMARTCAR_TEST_SECRET")

    def test_required_secret_rejects_placeholder_value(self):
        with patch.dict(os.environ, {"SMARTCAR_TEST_SECRET": "changeme"}, clear=True):
            with self.assertRaises(RuntimeError):
                get_required_secret("SMARTCAR_TEST_SECRET")

    def test_required_secret_rejects_short_value(self):
        with patch.dict(os.environ, {"SMARTCAR_TEST_SECRET": "short-but-not-placeholder"}, clear=True):
            with self.assertRaises(RuntimeError):
                get_required_secret("SMARTCAR_TEST_SECRET", min_length=32)

    def test_required_secret_accepts_sufficient_value(self):
        value = "uK9A5cM7vQ2bX4sN8rT1zP6dL3fH0jW5Y7eG2aC9"
        with patch.dict(os.environ, {"SMARTCAR_TEST_SECRET": value}, clear=True):
            self.assertEqual(get_required_secret("SMARTCAR_TEST_SECRET"), value)


if __name__ == "__main__":
    unittest.main()
