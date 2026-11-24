"""Negative controls for invalid enrolled hardware key Unicode (synthetic inputs)."""
import unittest

from hardware_transport_security import (
    HardwareEnvelopeVerifier,
    HardwareTransportError,
    derive_directional_key,
)

DEVICE = "pi-bench-001"
VALID = "device-secret-" + "x" * 48


class InvalidHardwareSecretUnicodeTests(unittest.TestCase):
    def test_enrollment_rejects_lone_surrogate(self):
        with self.assertRaises(HardwareTransportError) as caught:
            HardwareEnvelopeVerifier({DEVICE: VALID + "\ud800"})
        self.assertEqual(caught.exception.reason, "HW_DEVICE_SECRET_INVALID")

    def test_key_derivation_rejects_lone_surrogate(self):
        with self.assertRaises(HardwareTransportError) as caught:
            derive_directional_key(VALID + "\udfff", DEVICE, "TELEMETRY")
        self.assertEqual(caught.exception.reason, "HW_DEVICE_SECRET_INVALID")

    def test_valid_key_derives_deterministically(self):
        first = derive_directional_key(VALID, DEVICE, "TELEMETRY")
        self.assertEqual(first, derive_directional_key(VALID, DEVICE, "TELEMETRY"))
        self.assertEqual(len(first), 32)


if __name__ == "__main__":
    unittest.main()
