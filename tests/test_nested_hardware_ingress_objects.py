"""Negative controls for executable nested in-memory ingress objects.

These are synthetic security regressions, not original research effectiveness results.
"""
import unittest

from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError


class NestedIngressObjectsTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({"test-device": "x" * 48})

    def test_nested_custom_object_never_invokes_conversion(self):
        class Trap:
            def __str__(self):
                raise AssertionError("executed __str__")
            def __iter__(self):
                raise AssertionError("executed __iter__")
        with self.assertRaises(HardwareTransportError) as raised:
            self.verifier._parse({"payload": {"nested": [Trap()]}})
        self.assertEqual(raised.exception.reason, "HW_CANONICAL_ENCODING_INVALID")

    def test_nested_custom_dict_subclass_rejected(self):
        class TrapDict(dict):
            def items(self):
                raise AssertionError("executed items")
        with self.assertRaises(HardwareTransportError) as raised:
            self.verifier._parse({"payload": TrapDict({"a": 1})})
        self.assertEqual(raised.exception.reason, "HW_CANONICAL_ENCODING_INVALID")

    def test_nested_nonfinite_float_rejected(self):
        with self.assertRaises(HardwareTransportError) as raised:
            self.verifier._parse({"payload": [float("inf")]})
        self.assertEqual(raised.exception.reason, "HW_CANONICAL_ENCODING_INVALID")

    def test_ordinary_json_primitives_reach_schema_check(self):
        with self.assertRaises(HardwareTransportError) as raised:
            self.verifier._parse({"payload": [None, True, 1, 1.5, "ok"]})
        self.assertEqual(raised.exception.reason, "HW_ENVELOPE_FIELDS_INVALID")


if __name__ == "__main__":
    unittest.main()
