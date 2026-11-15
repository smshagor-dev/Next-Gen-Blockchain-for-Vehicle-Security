"""Synthetic transport regression tests; no physical or publication evidence."""
import unittest
from datetime import datetime, timezone
import hardware_transport_security as hws

DEVICE = "numeric-test-pi"
SECRET = "test-device-secret-" + "x" * 48

def sample():
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "HW:PI:TELEMETRY", "source": "bench",
        "speed": 1.0, "acceleration": 0.0, "fuel_level": 50.0,
        "battery_voltage": 12.0, "engine_temp": 25.0,
        "gps_lat": 0.0, "gps_lon": 0.0, "obstacle_distance": 20.0,
        "emergency_brake_active": False, "steering_angle": 0.0,
        "brake_pressure": 0.0, "throttle_position": 0.0,
        "rpm": 0.0, "odometer": 0.0,
        "driver_heart_rate_bpm": 70.0, "driver_drowsiness_score": 0.0,
        "driver_unwell": False,
    }

class NumericAndMetadataTests(unittest.TestCase):
    def test_huge_integer_returns_transport_error_not_overflow(self):
        payload = sample()
        payload["speed"] = 10 ** 1000
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_TELEMETRY_RANGE_INVALID_SPEED"):
            hws.validate_telemetry_payload(payload)

    def test_huge_negative_integer_returns_transport_error(self):
        payload = sample()
        payload["acceleration"] = -(10 ** 1000)
        with self.assertRaises(hws.HardwareTransportError):
            hws.validate_telemetry_payload(payload)

    def test_event_object_not_stringified(self):
        payload = sample()
        payload["event"] = {"event": "EMERGENCY"}
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_TELEMETRY_EVENT_INVALID"):
            hws.validate_telemetry_payload(payload)

    def test_event_boolean_not_stringified(self):
        payload = sample()
        payload["event"] = True
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_TELEMETRY_EVENT_INVALID"):
            hws.validate_telemetry_payload(payload)

    def test_source_array_not_stringified(self):
        payload = sample()
        payload["source"] = ["bench"]
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_TELEMETRY_SOURCE_INVALID"):
            hws.validate_telemetry_payload(payload)

    def test_timestamp_number_not_stringified(self):
        payload = sample()
        payload["timestamp"] = 1731628800
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_TELEMETRY_TIMESTAMP_INVALID"):
            hws.validate_telemetry_payload(payload)

    def test_valid_envelope_still_roundtrips(self):
        signed = hws.build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", sample())
        verified = hws.HardwareEnvelopeVerifier({DEVICE: SECRET}).verify(
            hws.encode_authenticated_envelope(signed), expected_kind="TELEMETRY")
        self.assertEqual(verified.payload["event"], "HW:PI:TELEMETRY")

if __name__ == "__main__":
    unittest.main()
