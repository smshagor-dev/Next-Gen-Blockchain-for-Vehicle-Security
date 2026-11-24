"""Negative controls for strict wire-level envelope field types.

Synthetic protocol cases only; no physical safety or research efficacy claim.
"""
import json
import unittest
from datetime import datetime, timezone

from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope, encode_authenticated_envelope,
    build_safe_stop_payload,
)

DEVICE = "bench-pi"
SECRET = "synthetic-bench-key-" + "x" * 40


class StrictEnvelopeFieldTypeTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({DEVICE: SECRET})
        self.envelope = build_authenticated_envelope(
            DEVICE, SECRET, "COMMAND", build_safe_stop_payload(),
            timestamp=datetime.now(timezone.utc),
        )

    def test_all_control_fields_reject_non_string_values(self):
        for field in ("version", "kind", "device_id", "timestamp", "nonce", "mac"):
            for value in (None, False, 1, [], {}):
                with self.subTest(field=field, value=value):
                    mutated = dict(self.envelope)
                    mutated[field] = value
                    with self.assertRaisesRegex(
                        HardwareTransportError, "HW_ENVELOPE_FIELD_TYPE_INVALID"
                    ):
                        self.verifier.verify(json.dumps(mutated).encode())

    def test_bad_type_does_not_consume_nonce(self):
        malformed = dict(self.envelope)
        malformed["device_id"] = [DEVICE]
        with self.assertRaisesRegex(
            HardwareTransportError, "HW_ENVELOPE_FIELD_TYPE_INVALID"
        ):
            self.verifier.verify(json.dumps(malformed).encode())
        accepted = self.verifier.verify(encode_authenticated_envelope(self.envelope))
        self.assertEqual(accepted.device_id, DEVICE)

    def test_replayed_valid_frame_still_rejected(self):
        frame = encode_authenticated_envelope(self.envelope)
        self.verifier.verify(frame)
        with self.assertRaises(HardwareTransportError):
            self.verifier.verify(frame)


if __name__ == "__main__":
    unittest.main()
