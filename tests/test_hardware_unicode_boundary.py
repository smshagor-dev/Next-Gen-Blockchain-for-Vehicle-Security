"""Synthetic negative controls for malformed Unicode at hardware ingress.

Not publishable V2X attack-effectiveness evidence.
"""
import unittest

from hardware_transport_security import (
    HardwareEnvelopeVerifier,
    HardwareTransportError,
    _canonical_bytes,
)


class HardwareUnicodeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({"device": "a" * 48})

    def test_raw_python_string_with_lone_surrogate_fails_closed(self):
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse('{"payload":"\\ud800"}'.replace("\\ud800", "\ud800"))
        self.assertEqual(caught.exception.reason, "HW_FRAME_UTF8_INVALID")

    def test_canonical_encoding_lone_surrogate_fails_closed(self):
        with self.assertRaises(HardwareTransportError) as caught:
            _canonical_bytes({"payload": "\ud800"})
        self.assertEqual(caught.exception.reason, "HW_CANONICAL_ENCODING_INVALID")

    def test_ordinary_utf8_still_reaches_schema_validation(self):
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse('{"payload":"valid café"}')
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_FIELDS_INVALID")


if __name__ == "__main__":
    unittest.main()
