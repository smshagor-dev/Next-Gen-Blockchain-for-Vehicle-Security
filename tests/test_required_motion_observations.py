"""Fail-closed signed motion and position ingestion regression tests.

Run: python -m unittest discover -s tests -p 'test_required_motion_observations.py'
"""
import unittest
from datetime import datetime, timezone

from hardware_bridge import to_telemetry


class RequiredMotionObservationsTests(unittest.TestCase):
    def setUp(self):
        self.pkt = {
            "speed": 0.0,
            "acceleration": 0.0,
            "gps_lat": 0.0,
            "gps_lon": 0.0,
            "emergency_brake_active": False,
            "driver_unwell": False,
            "obstacle_distance": 4.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def test_missing_motion_and_position_fail_closed(self):
        for field in ("speed", "acceleration", "gps_lat", "gps_lon"):
            with self.subTest(field=field):
                pkt = dict(self.pkt)
                del pkt[field]
                with self.assertRaisesRegex(ValueError, field):
                    to_telemetry(pkt)

    def test_explicit_zero_is_valid_not_missing(self):
        telemetry = to_telemetry(self.pkt)
        self.assertEqual(telemetry.speed, 0.0)
        self.assertEqual(telemetry.gps_lat, 0.0)

    def test_non_numeric_motion_and_position_fail(self):
        for field in ("speed", "acceleration", "gps_lat", "gps_lon"):
            with self.subTest(field=field):
                pkt = dict(self.pkt)
                pkt[field] = "0"
                with self.assertRaises(ValueError):
                    to_telemetry(pkt)


if __name__ == "__main__":
    unittest.main()
