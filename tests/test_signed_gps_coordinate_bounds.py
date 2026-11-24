"""Fail-closed signed GPS coordinate boundary tests; no vehicle actuation."""
import unittest
from hardware_bridge import _validated_gps_coordinate, to_telemetry


class SignedGPSCoordinateTests(unittest.TestCase):
    def test_boundary_coordinates_are_valid(self):
        for field, values in (("gps_lat", (-90, 0, 90)), ("gps_lon", (-180, 0, 180))):
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertEqual(_validated_gps_coordinate(value, field), float(value))

    def test_outside_coordinate_bounds_rejected(self):
        for field, values in (("gps_lat", (-90.001, 90.001)), ("gps_lon", (-180.001, 180.001))):
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        _validated_gps_coordinate(value, field)

    def test_conversion_rejects_out_of_domain_coordinates(self):
        packet = {"speed": 0.0, "acceleration": 0.0, "gps_lat": 0.0,
                  "gps_lon": 0.0, "obstacle_distance": 4.0,
                  "emergency_brake_active": False, "driver_unwell": False,
                  "timestamp": "2026-11-15T12:00:01Z"}
        for field, value in (("gps_lat", 91.0), ("gps_lon", -181.0)):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    to_telemetry(dict(packet, **{field: value}))
        telemetry = to_telemetry(dict(packet, gps_lat=-90.0, gps_lon=180.0))
        self.assertEqual(telemetry.gps_lat, -90.0)
        self.assertEqual(telemetry.gps_lon, 180.0)

    def test_unknown_coordinate_field_rejected(self):
        with self.assertRaises(ValueError):
            _validated_gps_coordinate(0, "unknown")

    def test_non_numeric_and_nonfinite_rejected(self):
        for value in (True, None, "45", float("nan"), float("inf"), [], {}):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    _validated_gps_coordinate(value, "gps_lat")


if __name__ == "__main__":
    unittest.main()
