"""Synthetic executable/config pin integrity regressions, not HIL evidence."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from capture_export_producer import canonical
from pin_policy_artifacts import build_pin, verify_pin, sha


class PolicyArtifactPinTests(unittest.TestCase):
    def setUp(self):
        self.manifest = canonical({"baseline_name": "auth-only",
                                   "candidate_name": "evidence-gate"})
        self.args = (self.manifest, b"binary-one", b"binary-two",
                     b'{"threshold":1}', b'{"threshold":2}')
        self.pin = build_pin(*self.args, "auth-only", "evidence-gate")
        self.digest = sha(self.pin)

    def test_valid_pin(self):
        result = verify_pin(self.pin, self.digest, *self.args)
        self.assertTrue(result["pin_verified"])
        self.assertFalse(result["publication_ready"])

    def test_modified_baseline_binary_fails(self):
        with self.assertRaisesRegex(ValueError, "artifact digest"):
            verify_pin(self.pin, self.digest, self.args[0], b"binary-one-tampered", *self.args[2:])

    def test_modified_candidate_binary_fails(self):
        with self.assertRaisesRegex(ValueError, "artifact digest"):
            verify_pin(self.pin, self.digest, self.args[0], self.args[1],
                       b"binary-two-tampered", *self.args[3:])

    def test_modified_baseline_config_fails(self):
        with self.assertRaisesRegex(ValueError, "artifact digest"):
            verify_pin(self.pin, self.digest, *self.args[:3], b'{"threshold":99}', self.args[4])

    def test_modified_candidate_config_fails(self):
        with self.assertRaisesRegex(ValueError, "artifact digest"):
            verify_pin(self.pin, self.digest, *self.args[:4], b'{"threshold":99}')

    def test_swapped_executables_fail(self):
        with self.assertRaisesRegex(ValueError, "artifact digest"):
            verify_pin(self.pin, self.digest, self.args[0], self.args[2], self.args[1],
                       *self.args[3:])

    def test_external_pin_mismatch_fails(self):
        with self.assertRaisesRegex(ValueError, "external executable pin"):
            verify_pin(self.pin, "0" * 64, *self.args)

    def test_extra_schema_field_fails(self):
        payload = json.loads(self.pin)
        payload["attacker"] = "unexpected"
        forged = canonical(payload)
        with self.assertRaisesRegex(ValueError, "schema"):
            verify_pin(forged, sha(forged), *self.args)

    def test_duplicate_key_fails(self):
        forged = self.pin.replace(b'"schema_version":', b'"schema_version":1,"schema_version":')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_pin(forged, sha(forged), *self.args)

    def test_wrong_policy_name_fails(self):
        with self.assertRaisesRegex(ValueError, "policy names"):
            build_pin(*self.args, "not-the-baseline", "evidence-gate")

    def test_empty_binary_fails(self):
        with self.assertRaisesRegex(ValueError, "nonempty"):
            build_pin(self.args[0], b"", *self.args[2:], "auth-only", "evidence-gate")

    def test_bool_version_fails(self):
        payload = json.loads(self.pin)
        payload["schema_version"] = True
        forged = canonical(payload)
        with self.assertRaisesRegex(ValueError, "schema"):
            verify_pin(forged, sha(forged), *self.args)


if __name__ == "__main__":
    unittest.main()
