"""Fail-closed controls for user-defined Mapping objects at hardware admission.

These are synthetic security regressions, not original research effectiveness results.
"""
import unittest
from collections.abc import Mapping
from types import MappingProxyType

from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError


class ExecutableMapping(Mapping):
    calls = 0

    def __iter__(self):
        self.calls += 1
        raise AssertionError("untrusted iterator executed")

    def __len__(self):
        self.calls += 1
        raise AssertionError("untrusted length executed")

    def __getitem__(self, key):
        self.calls += 1
        raise AssertionError("untrusted item access executed")


class CustomMappingRejectionTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier(
            {"vehicle-a": "a" * 40}, max_frame_bytes=1024
        )

    def test_custom_mapping_rejected_without_callbacks(self):
        frame = ExecutableMapping()
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse(frame)
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_TYPE_INVALID")
        self.assertFalse(caught.exception.authenticated)
        self.assertEqual(frame.calls, 0)

    def test_mapping_proxy_rejected_without_copy(self):
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse(MappingProxyType({"payload": "small"}))
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_TYPE_INVALID")

    def test_builtin_dict_still_reaches_schema_gate(self):
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier._parse({"payload": "small"})
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_FIELDS_INVALID")


if __name__ == "__main__":
    unittest.main()
