"""Non-actuating negative controls for signed obstacle measurement omission.

An authenticated MAC authenticates omissions too: a missing obstacle distance
must not be silently converted to 999 m (an apparently clear road).
"""
import unittest
from datetime import datetime, timezone
from hardware_bridge import to_telemetry


def packet():
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "emergency_brake_active": False,
        "driver_unwell": False,
        "obstacle_distance": 4.0,
        "speed": 0.0, "acceleration": 0.0, "gps_lat": 0.0, "gps_lon": 0.0,
    }


class SignedObstacleMeasurementTests(unittest.TestCase):
    def test_missing_obstacle_distance_rejected(self):
        sample = packet()
        del sample["obstacle_distance"]
        with self.assertRaisesRegex(ValueError, "obstacle_distance"):
            to_telemetry(sample)

    def test_explicit_zero_distance_retained(self):
        sample = packet()
        sample["obstacle_distance"] = 0.0
        self.assertEqual(to_telemetry(sample).obstacle_distance, 0.0)

    def test_nonfinite_obstacle_distance_rejected(self):
        sample = packet()
        sample["obstacle_distance"] = float("inf")
        with self.assertRaisesRegex(ValueError, "obstacle_distance"):
            to_telemetry(sample)

    def test_string_obstacle_distance_rejected(self):
        sample = packet()
        sample["obstacle_distance"] = "999"
        with self.assertRaisesRegex(ValueError, "obstacle_distance"):
            to_telemetry(sample)


if __name__ == "__main__":
    unittest.main()
