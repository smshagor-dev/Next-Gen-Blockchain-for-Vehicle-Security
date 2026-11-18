"""Non-actuating, real-verifier negative control for partial-batch replay claims.

Run: python -m unittest discover -s tests -p 'test_ingress_batch_atomicity.py' -v
This test documents an availability failure mode, not an actuator exploit.
"""
import copy
import unittest
from datetime import datetime, timezone

from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope, encode_authenticated_envelope,
)
from hardware_bridge import AuthenticatedPiTelemetrySession


DEVICE = "bench_pi"
SECRET = "local-test-only-secret-with-32-plus-characters"


def payload():
    now = datetime.now(timezone.utc).isoformat()
    return {
        "speed": 0, "acceleration": 0, "fuel_level": 80,
        "battery_voltage": 12.6, "engine_temp": 20,
        "gps_lat": 0, "gps_lon": 0, "obstacle_distance": 20,
        "emergency_brake_active": False, "steering_angle": 0,
        "brake_pressure": 0, "throttle_position": 0, "rpm": 0,
        "odometer": 1, "driver_heart_rate_bpm": 72,
        "driver_drowsiness_score": 0, "driver_unwell": False,
        "timestamp": now, "event": "BENCH_OBSERVATION",
    }


class BatchFailureNegativeControl(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({DEVICE: SECRET})

    def frame(self, nonce):
        return encode_authenticated_envelope(
            build_authenticated_envelope(
                DEVICE, SECRET, "TELEMETRY", payload(), nonce=nonce
            )
        )

    def test_valid_single_frame_is_admitted(self):
        frame = self.frame("11" * 16)
        self.assertEqual(len(AuthenticatedPiTelemetrySession(self.verifier).receive(frame)), 1)

    def test_later_invalid_frame_consumes_earlier_nonce_without_delivery(self):
        first = self.frame("22" * 16)
        second = bytearray(self.frame("33" * 16))
        # Invalid MAC on the second frame; the first was verified and its
        # nonce claimed, but receive() raises before returning its list.
        second[10] = ord("X") if second[10] != ord("X") else ord("Y")
        with self.assertRaises(HardwareTransportError):
            AuthenticatedPiTelemetrySession(self.verifier).receive(first + bytes(second))
        with self.assertRaises(HardwareTransportError) as caught:
            AuthenticatedPiTelemetrySession(self.verifier).receive(first)
        self.assertEqual(caught.exception.reason, "HW_REPLAY_DETECTED")

    def test_batch_failure_does_not_claim_later_valid_nonce(self):
        first = self.frame("44" * 16)
        second = bytearray(self.frame("55" * 16))
        second[10] = ord("X") if second[10] != ord("X") else ord("Y")
        third = self.frame("66" * 16)
        with self.assertRaises(HardwareTransportError):
            AuthenticatedPiTelemetrySession(self.verifier).receive(first + bytes(second) + third)
        self.assertEqual(len(AuthenticatedPiTelemetrySession(self.verifier).receive(third)), 1)

    def test_independent_fresh_frame_remains_available(self):
        first = self.frame("77" * 16)
        invalid = b'{"invalid":true}\n'
        with self.assertRaises(HardwareTransportError):
            AuthenticatedPiTelemetrySession(self.verifier).receive(first + invalid)
        fresh = self.frame("88" * 16)
        self.assertEqual(len(AuthenticatedPiTelemetrySession(self.verifier).receive(fresh)), 1)


if __name__ == "__main__":
    unittest.main()
