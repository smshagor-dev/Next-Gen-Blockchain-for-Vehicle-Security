"""Synthetic signed-observation timestamp regressions; no hardware claims."""
import unittest
from datetime import datetime, timezone

from hardware_bridge import _signed_observation_timestamp, to_telemetry


class ObservationTimestampTests(unittest.TestCase):
    def test_explicit_utc_z_is_normalized(self):
        self.assertEqual(_signed_observation_timestamp("2026-11-15T12:00:01Z"),
                         "2026-11-15T12:00:01+00:00")

    def test_explicit_utc_offset_is_preserved(self):
        self.assertEqual(_signed_observation_timestamp("2026-11-15T12:00:01.123+00:00"),
                         "2026-11-15T12:00:01.123000+00:00")

    def test_naive_and_non_utc_are_rejected(self):
        for value in ("2026-11-15T12:00:01", "2026-11-15T12:00:01+01:00",
                      "2026-11-15T12:00:01-00:00"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _signed_observation_timestamp(value)

    def test_missing_invalid_and_unbounded_are_rejected(self):
        for value in (None, 123, True, "", "2026-02-30T12:00:01Z",
                      "2026-11-15 12:00:01Z", "20261115T120001Z",
                      "2026-11-15T12:00:01,2Z", "X" * 1000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _signed_observation_timestamp(value)

    def test_telemetry_never_invents_missing_observation_time(self):
        with self.assertRaisesRegex(ValueError, "timestamp"):
            to_telemetry({"emergency_brake_active": False, "driver_unwell": False,
                          "obstacle_distance": 4.0, "speed": 0.0, "acceleration": 0.0, "gps_lat": 0.0, "gps_lon": 0.0})

    def test_telemetry_preserves_valid_observation_time(self):
        result = to_telemetry({"timestamp": "2026-11-15T12:00:01Z",
                               "emergency_brake_active": False, "driver_unwell": False,
                               "obstacle_distance": 4.0, "speed": 0.0, "acceleration": 0.0, "gps_lat": 0.0, "gps_lon": 0.0})
        self.assertEqual(result.timestamp, "2026-11-15T12:00:01+00:00")


if __name__ == "__main__":
    unittest.main()
