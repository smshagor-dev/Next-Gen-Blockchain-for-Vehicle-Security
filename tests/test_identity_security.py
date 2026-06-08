import os
import unittest
from pathlib import Path
from unittest.mock import patch

from identity_security import (
    OPEN_REGISTRATION,
    OPEN_REGISTRATION_SYBIL_WARNING,
    identity_security_metadata,
)


class IdentitySecurityTests(unittest.TestCase):
    def test_open_registration_has_no_sybil_resistance(self):
        with patch.dict(os.environ, {"SMARTCAR_IDENTITY_ADMISSION_POLICY": OPEN_REGISTRATION}, clear=False):
            metadata = identity_security_metadata()
        self.assertTrue(metadata["identity_authenticity"])
        self.assertFalse(metadata["sybil_resistance"])
        self.assertEqual(metadata["identity_admission_policy"], OPEN_REGISTRATION)
        self.assertEqual(metadata["warning"], OPEN_REGISTRATION_SYBIL_WARNING)

    def test_gui_never_displays_sybil_resistant(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertNotIn("Sybil Resistant", text)

    def test_lamport_did_docs_do_not_claim_sybil_defense(self):
        did_text = Path("did_identity.py").read_text(encoding="utf-8").lower()
        forbidden = [
            "prevents sybil",
            "sybil-resistant identity layer",
            "computationally expensive",
            "preimage hardness prevents sybil",
        ]
        for phrase in forbidden:
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
