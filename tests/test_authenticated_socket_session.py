"""Real loopback socket tests for authenticated Pi session framing.

Uses production verifier and session classes, but not run_pi_mode or physical hardware.
These are regression tests, not independent research experiments.
"""
import socket
import unittest
from datetime import datetime, timezone

from hardware_bridge import AuthenticatedPiTelemetrySession, to_telemetry
from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope, encode_authenticated_envelope,
)

DEVICE = "loopback-pi"
SECRET = "loopback-only-test-key-material-0123456789abcdef"


def payload():
    from hardware_transport_security import _NUMERIC_RANGES
    fields = {name: (lo + hi) / 2 for name, (lo, hi) in _NUMERIC_RANGES.items()}
    fields.update(event="BENCH_OBSERVATION", timestamp=datetime.now(timezone.utc).isoformat(),
                  emergency_brake_active=False, driver_unwell=False)
    return fields


class AuthenticatedSocketSessionTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({DEVICE: SECRET}, replay_cache_entries=128)
        self.client, self.server = socket.socketpair()
        self.client.settimeout(2)
        self.server.settimeout(2)

    def tearDown(self):
        self.client.close()
        self.server.close()

    def send_and_receive(self, session, wire, chunk_size=17):
        # A real socket transport; deliberately fragment the signed envelope.
        self.client.sendall(wire)
        results = []
        remaining = len(wire)
        while remaining:
            data = self.server.recv(min(chunk_size, remaining))
            self.assertTrue(data)
            remaining -= len(data)
            results.extend(session.receive(data))
        return results

    def signed(self, nonce=None):
        kwargs = {"nonce": nonce} if nonce is not None else {}
        return encode_authenticated_envelope(
            build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", payload(), **kwargs)
        )

    def test_fragmented_authenticated_frame_is_admitted_once(self):
        session = AuthenticatedPiTelemetrySession(self.verifier)
        items = self.send_and_receive(session, self.signed(), chunk_size=7)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].device_id, DEVICE)
        self.assertIsNotNone(to_telemetry(items[0].payload))

    def test_replay_across_distinct_tcp_sessions_rejected(self):
        wire = self.signed(nonce="cd" * 16)
        self.assertEqual(len(self.send_and_receive(
            AuthenticatedPiTelemetrySession(self.verifier), wire)), 1)
        with self.assertRaises(HardwareTransportError):
            self.send_and_receive(AuthenticatedPiTelemetrySession(self.verifier), wire)

    def test_mac_tamper_does_not_consume_valid_nonce(self):
        import json
        signed = build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", payload())
        altered = json.loads(json.dumps(signed))
        altered["payload"]["speed"] = 999.0
        with self.assertRaises(HardwareTransportError):
            self.send_and_receive(AuthenticatedPiTelemetrySession(self.verifier),
                                  encode_authenticated_envelope(altered))
        accepted = self.send_and_receive(AuthenticatedPiTelemetrySession(self.verifier),
                                         encode_authenticated_envelope(signed))
        self.assertEqual(len(accepted), 1)

    def test_missing_signed_safety_state_fails_closed_before_conversion(self):
        bad = payload()
        bad.pop("driver_unwell")
        wire = encode_authenticated_envelope(
            build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", bad))
        try:
            items = self.send_and_receive(AuthenticatedPiTelemetrySession(self.verifier), wire)
        except HardwareTransportError:
            return  # Transport schema itself may reject the missing field.
        self.assertEqual(len(items), 1)
        with self.assertRaises((ValueError, HardwareTransportError)):
            to_telemetry(items[0].payload)


if __name__ == "__main__":
    unittest.main()
