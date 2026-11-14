"""Executable AST-isolated telemetry validation tests; no hardware dependencies."""
import ast
import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "hardware_bridge.py"
tree = ast.parse(SOURCE.read_text(encoding="utf-8-sig"))
names = {"_finite_telemetry_number", "_strict_telemetry_bool", "to_telemetry"}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
assert {n.name for n in nodes} == names
# Isolate the real functions while replacing the blockchain dataclass with a
# transparent constructor, so this test does not need hardware or a running chain.
namespace = {"TelemetryData": lambda **kwargs: kwargs}
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"), namespace)
convert = namespace["to_telemetry"]


class SignedTelemetryValidationTests(unittest.TestCase):
    def test_rejects_nonfinite_signed_fields(self):
        for field in ("speed", "acceleration", "gps_lat", "brake_pressure", "rpm"):
            for value in (float("nan"), float("inf"), float("-inf"), "NaN", "Infinity"):
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaises(ValueError):
                        convert({"event": "NORMAL", field: value})

    def test_rejects_ambiguous_safety_boolean(self):
        for field in ("emergency_brake_active", "driver_unwell"):
            for value in ("false", "true", 0, 1, None):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        convert({field: value})

    def test_valid_finite_packet(self):
        result = convert({"speed": 12.5, "emergency_brake_active": False,
                          "driver_unwell": True})
        self.assertEqual(result["speed"], 12.5)
        self.assertFalse(result["emergency_brake_active"])
        self.assertTrue(result["driver_unwell"])

    def test_rejects_coercible_strings_and_containers(self):
        # MAC validity does not make a JSON string a sensor number.
        for field in ("speed", "gps_lon", "obstacle_distance", "brake_pressure"):
            for value in ("0", "12.5", "1e309", "", None, [], {}, [12]):
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaises(ValueError):
                        convert({field: value})

    def test_preserves_valid_integer_and_float_numbers(self):
        result = convert({"speed": 0, "rpm": 1250, "gps_lat": -33.8})
        self.assertEqual(result["speed"], 0.0)
        self.assertEqual(result["rpm"], 1250.0)
        self.assertEqual(result["gps_lat"], -33.8)

    def test_rejects_bool_in_numeric_field(self):
        with self.assertRaises(ValueError):
            convert({"speed": True})


if __name__ == "__main__":
    unittest.main()
