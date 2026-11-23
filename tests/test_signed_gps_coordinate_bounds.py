"""Fail-closed signed GPS coordinate boundary tests; no vehicle actuation."""
import unittest
from hardware_bridge import _validated_gps_coordinate


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

    def test_non_numeric_and_nonfinite_rejected(self):
        for value in (True, None, "45", float("nan"), float("inf"), [], {}):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    _validated_gps_coordinate(value, "gps_lat")


if __name__ == "__main__":
    unittest.main()
