"""Fail-closed programmatic mapping ingress boundary regression tests."""
import unittest
from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError

class MappingIngressBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({"test-node": "x" * 48}, max_frame_bytes=1024)

    def test_large_mapping_rejected_before_authentication(self):
        with self.assertRaises(HardwareTransportError) as ctx:
            self.verifier.verify({"payload": {"event": "X" * 4096}})
        self.assertEqual(ctx.exception.reason, "HW_FRAME_TOO_LARGE")
        self.assertFalse(ctx.exception.authenticated)

    def test_deep_mapping_rejected_without_recursion_escape(self):
        value = {}
        root = value
        for _ in range(1500):
            child = {}
            value["nested"] = child
            value = child
        with self.assertRaises(HardwareTransportError) as ctx:
            self.verifier.verify(root)
        self.assertEqual(ctx.exception.reason, "HW_FRAME_TOO_LARGE")
        self.assertFalse(ctx.exception.authenticated)

    def test_small_mapping_still_reaches_schema_validation(self):
        with self.assertRaises(HardwareTransportError) as ctx:
            self.verifier.verify({"unexpected": 1})
        self.assertEqual(ctx.exception.reason, "HW_ENVELOPE_FIELDS_INVALID")

if __name__ == "__main__":
    unittest.main()
