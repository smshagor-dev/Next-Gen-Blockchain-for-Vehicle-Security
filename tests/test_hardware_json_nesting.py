"""Fail-closed hardware ingress regression for adversarial JSON nesting.

No vehicle, actuator, or network device is used.
"""
import unittest

from hardware_transport_security import HardwareTransportError, HardwareEnvelopeVerifier


class HardwareJSONNestingTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier(
            {"lab-device": "a" * 48}, max_frame_bytes=32768
        )

    def test_excessive_nesting_is_transport_error_not_recursion_error(self):
        raw = '{"payload":' + "[" * 1500 + "0" + "]" * 1500 + "}"
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier.verify(raw)
        self.assertEqual(caught.exception.reason, "HW_JSON_NESTING_EXCEEDED")
        self.assertFalse(caught.exception.authenticated)

    def test_deep_nesting_cannot_claim_nonce(self):
        raw = '{"payload":' + "[" * 1500 + "0" + "]" * 1500 + "}"
        for _ in range(3):
            with self.assertRaises(HardwareTransportError) as caught:
                self.verifier.verify(raw.encode("utf-8"))
            self.assertEqual(caught.exception.reason, "HW_JSON_NESTING_EXCEEDED")
        for cache in self.verifier._replay.values():
            self.assertEqual(len(cache), 0)

    def test_normal_shallow_json_remains_regular_envelope_rejection(self):
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier.verify('{"payload":{"a":[1,2]}}')
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_FIELDS_INVALID")


if __name__ == "__main__":
    unittest.main()
