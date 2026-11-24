"""Regression controls for in-process hardware envelope admission.

These tests are security contracts, not V2X research effectiveness results.
"""
import unittest

from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError


class MappingFrameBudgetTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier(
            {"vehicle-a": "a" * 40}, max_frame_bytes=1024
        )

    def test_oversized_mapping_rejected_before_authentication(self):
        frame = {"payload": {"event": "x" * 2048}}
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse(frame)
        self.assertEqual(caught.exception.reason, "HW_FRAME_TOO_LARGE")
        self.assertFalse(caught.exception.authenticated)

    def test_mapping_at_budget_still_checks_schema(self):
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse({"payload": "small"})
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_FIELDS_INVALID")

    def test_mapping_not_mutated_on_rejection(self):
        frame = {"payload": {"event": "x" * 2048}}
        with self.assertRaises(HardwareTransportError):
            self.verifier._parse(frame)
        self.assertEqual(len(frame["payload"]["event"]), 2048)


if __name__ == "__main__":
    unittest.main()
