"""Safety-negative protocol tests. No physical actuation or vehicle safety claim."""
import unittest
from datetime import datetime, timedelta, timezone

from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope, build_safe_stop_payload,
    derive_directional_key, encode_authenticated_envelope,
)

DEVICE = "bench-ecu-01"
SECRET = "local-bench-key-" + "K" * 48


class CommandProtocolConformanceTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({DEVICE: SECRET})
        self.payload = build_safe_stop_payload(block_index=42)

    def command(self, **kwargs):
        return build_authenticated_envelope(
            DEVICE, SECRET, "COMMAND", self.payload, **kwargs
        )

    def test_directional_keys_are_distinct(self):
        self.assertNotEqual(
            derive_directional_key(SECRET, DEVICE, "COMMAND"),
            derive_directional_key(SECRET, DEVICE, "TELEMETRY"),
        )

    def test_signed_command_verifies_once(self):
        frame = encode_authenticated_envelope(self.command())
        result = self.verifier.verify(frame, expected_kind="COMMAND")
        self.assertEqual(result.payload["cmd"], "SAFE_MODE_STOP")
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier.verify(frame, expected_kind="COMMAND")
        self.assertEqual(caught.exception.reason, "HW_REPLAY_DETECTED")

    def test_command_cannot_be_accepted_as_telemetry(self):
        frame = encode_authenticated_envelope(self.command())
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier.verify(frame, expected_kind="TELEMETRY")
        self.assertEqual(caught.exception.reason, "HW_MESSAGE_DIRECTION_INVALID")

    def test_modified_command_is_rejected(self):
        command = self.command()
        command["payload"]["brake_pressure"] = 0
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier.verify(command, expected_kind="COMMAND")
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_MAC_INVALID")

    def test_stale_command_is_rejected(self):
        command = self.command(timestamp=datetime.now(timezone.utc) - timedelta(minutes=2))
        with self.assertRaises(HardwareTransportError) as caught:
            self.verifier.verify(command, expected_kind="COMMAND")
        self.assertEqual(caught.exception.reason, "HW_ENVELOPE_STALE")

    def test_different_device_cannot_reuse_mac(self):
        command = self.command()
        command["device_id"] = "other-bench-ecu"
        with self.assertRaises(HardwareTransportError):
            self.verifier.verify(command, expected_kind="COMMAND")

    def test_valid_mac_does_not_authorize_unsafe_command(self):
        unsafe = dict(self.payload)
        unsafe["cmd"] = "SET_THROTTLE"
        with self.assertRaises(HardwareTransportError):
            build_authenticated_envelope(DEVICE, SECRET, "COMMAND", unsafe)

    def test_restart_replay_gap_is_explicit(self):
        # A fresh in-memory verifier has no persisted nonce state.
        # This is a documented failing security property, not a passing
        # claim of durable anti-replay.
        frame = encode_authenticated_envelope(self.command())
        self.verifier.verify(frame, expected_kind="COMMAND")
        restarted = HardwareEnvelopeVerifier({DEVICE: SECRET})
        accepted = restarted.verify(frame, expected_kind="COMMAND")
        self.assertEqual(accepted.payload["cmd"], "SAFE_MODE_STOP")


if __name__ == "__main__":
    unittest.main()
