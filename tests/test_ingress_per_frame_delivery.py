"""Non-actuating regression tests for per-frame ingress delivery semantics."""
import unittest
from datetime import datetime, timezone

from hardware_bridge import AuthenticatedPiTelemetrySession
from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope, encode_authenticated_envelope,
)

DEVICE = "bench_pi"
SECRET = "local-test-only-secret-with-32-plus-characters"


def payload():
    return {
        "speed": 0, "acceleration": 0, "fuel_level": 80,
        "battery_voltage": 12.6, "engine_temp": 20,
        "gps_lat": 0, "gps_lon": 0, "obstacle_distance": 20,
        "emergency_brake_active": False, "steering_angle": 0,
        "brake_pressure": 0, "throttle_position": 0, "rpm": 0,
        "odometer": 1, "driver_heart_rate_bpm": 72,
        "driver_drowsiness_score": 0, "driver_unwell": False,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "BENCH_OBSERVATION",
    }


def frame(nonce):
    return encode_authenticated_envelope(
        build_authenticated_envelope(
            DEVICE, SECRET, "TELEMETRY", payload(), nonce=nonce
        )
    )


class PerFrameIngressTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({DEVICE: SECRET})
        self.session = AuthenticatedPiTelemetrySession(self.verifier)

    def test_first_valid_delivered_before_later_bad_mac(self):
        good = frame("11" * 16)
        bad = bytearray(frame("22" * 16))
        bad[10] = ord("X") if bad[10] != ord("X") else ord("Y")
        delivered = []
        with self.assertRaises(HardwareTransportError):
            for item in self.session.receive_iter(good + bytes(bad)):
                delivered.append(item.nonce)
        self.assertEqual(delivered, ["11" * 16])
        with self.assertRaisesRegex(HardwareTransportError, "HW_REPLAY_DETECTED"):
            list(AuthenticatedPiTelemetrySession(self.verifier).receive_iter(good))

    def test_fragmentation_yields_only_complete_frames(self):
        good = frame("33" * 16)
        self.assertEqual(list(self.session.receive_iter(good[:20])), [])
        items = list(self.session.receive_iter(good[20:]))
        self.assertEqual([i.nonce for i in items], ["33" * 16])

    def test_replay_rejected_without_delivering_duplicate(self):
        good = frame("44" * 16)
        self.assertEqual(len(list(self.session.receive_iter(good))), 1)
        delivered = []
        with self.assertRaisesRegex(HardwareTransportError, "HW_REPLAY_DETECTED"):
            for item in self.session.receive_iter(good):
                delivered.append(item)
        self.assertEqual(delivered, [])

    def test_legacy_receive_keeps_eager_contract(self):
        self.assertEqual(len(self.session.receive(frame("55" * 16))), 1)


if __name__ == "__main__":
    unittest.main()
