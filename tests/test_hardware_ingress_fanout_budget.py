"""Regression controls for pre-expansion ingress worklist bounds.

These synthetic tests are engineering controls, not attack-effectiveness data.
"""
import unittest

from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError


class HardwareIngressFanoutBudgetTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier(
            {"test-device": "a" * 48}, max_frame_bytes=1024
        )

    def test_wide_dict_rejected_before_schema(self):
        envelope = {"payload": {str(i): i for i in range(1100)}}
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse(envelope)
        self.assertEqual(caught.exception.reason, "HW_FRAME_TOO_LARGE")

    def test_wide_list_rejected_before_schema(self):
        envelope = {"payload": [None] * 1100}
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse(envelope)
        self.assertEqual(caught.exception.reason, "HW_FRAME_TOO_LARGE")

    def test_small_invalid_dict_reaches_schema_check(self):
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse({"payload": [None, 1, "ok"]})
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_FIELDS_INVALID")


if __name__ == "__main__":
    unittest.main()
