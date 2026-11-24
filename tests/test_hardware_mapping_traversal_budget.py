"""Bounded in-process envelope traversal: synthetic negative controls only."""
import unittest
from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError

class MappingTraversalBudgetTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({"vehicle-a": "a" * 40}, max_frame_bytes=1024)

    def reject(self, value):
        with self.assertRaises(HardwareTransportError) as error:
            self.verifier._parse(value)
        self.assertEqual(error.exception.reason, "HW_FRAME_TOO_LARGE")
        self.assertFalse(error.exception.authenticated)

    def test_deep_mapping_rejected_before_json_encoder(self):
        root = {}
        current = root
        for _ in range(40):
            child = {}
            current["nested"] = child
            current = child
        self.reject(root)

    def test_cyclic_mapping_rejected(self):
        root = {}
        root["self"] = root
        self.reject(root)

    def test_wide_mapping_rejected(self):
        self.reject({"payload": list(range(1200))})

    def test_small_mapping_still_reaches_schema_validation(self):
        with self.assertRaises(HardwareTransportError) as error:
            self.verifier._parse({"payload": "small"})
        self.assertEqual(error.exception.reason, "HW_ENVELOPE_FIELDS_INVALID")

if __name__ == "__main__":
    unittest.main()
