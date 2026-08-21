import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from identity_security import (
    DENY_UNCONFIGURED,
    OPEN_REGISTRATION,
    OPEN_REGISTRATION_SYBIL_WARNING,
    VEHICLE_MANUFACTURER_REGISTRY,
    identity_security_metadata,
)


class IdentitySecurityTests(unittest.TestCase):
    def test_missing_policy_fails_closed_instead_of_open_registration(self):
        with patch.dict(os.environ, {}, clear=True):
            metadata = identity_security_metadata()
        self.assertEqual(metadata["identity_admission_policy"], DENY_UNCONFIGURED)
        self.assertTrue(metadata["default_fail_closed"])
        self.assertTrue(metadata["identity_admission_enforced"])
        self.assertFalse(metadata["sybil_resistance"])

    def test_open_registration_is_explicit_and_has_no_sybil_resistance(self):
        with patch.dict(os.environ, {"SMARTCAR_IDENTITY_ADMISSION_POLICY": OPEN_REGISTRATION}, clear=True):
            metadata = identity_security_metadata()
        self.assertTrue(metadata["identity_authenticity"])
        self.assertFalse(metadata["sybil_resistance"])
        self.assertEqual(metadata["identity_admission_policy"], OPEN_REGISTRATION)
        self.assertEqual(metadata["warning"], OPEN_REGISTRATION_SYBIL_WARNING)
        self.assertTrue(metadata["open_registration_explicit_only"])

    def test_registry_policy_requires_enrolled_identity_registry(self):
        env = {
            "SMARTCAR_IDENTITY_ADMISSION_POLICY": VEHICLE_MANUFACTURER_REGISTRY,
            "SMARTCAR_SYNC_VEHICLE_KEYS_JSON": "{}",
        }
        with patch.dict(os.environ, env, clear=True):
            metadata = identity_security_metadata()
        self.assertFalse(metadata["admission_registry_configured"])
        self.assertFalse(metadata["sybil_resistance"])
        self.assertTrue(metadata["identity_admission_enforced"])

    def test_registry_policy_with_enrollment_reports_limited_identity_creation(self):
        env = {
            "SMARTCAR_IDENTITY_ADMISSION_POLICY": VEHICLE_MANUFACTURER_REGISTRY,
            "SMARTCAR_SYNC_VEHICLE_KEYS_JSON": json.dumps({"CAR1": "x" * 48}),
        }
        with patch.dict(os.environ, env, clear=True):
            metadata = identity_security_metadata()
        self.assertTrue(metadata["admission_registry_configured"])
        self.assertEqual(metadata["admission_registry_identity_count"], 1)
        self.assertTrue(metadata["sybil_resistance"])
        self.assertFalse(metadata["secret_values_exposed"])
        self.assertNotIn("x" * 48, repr(metadata))

    def test_gui_never_displays_sybil_resistant(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertNotIn("Sybil Resistant", text)

    def test_lamport_did_docs_do_not_claim_sybil_defense(self):
        did_text = Path("did_identity.py").read_text(encoding="utf-8").lower()
        for phrase in [
            "prevents sybil", "sybil-resistant identity layer",
            "computationally expensive", "preimage hardness prevents sybil",
        ]:
            self.assertNotIn(phrase, did_text)

    def test_identity_security_doc_exists(self):
        doc = Path("docs/identity-security-model.md")
        self.assertTrue(doc.exists())
        text = doc.read_text(encoding="utf-8")
        self.assertIn("Identity Authenticity", text)
        self.assertIn("Sybil Attack Definition", text)
        self.assertIn("OPEN_REGISTRATION", text)


if __name__ == "__main__":
    unittest.main()
