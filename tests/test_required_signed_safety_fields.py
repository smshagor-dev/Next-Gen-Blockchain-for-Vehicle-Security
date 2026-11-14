"""Executable source-isolated tests: no hardware or blockchain import required."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "hardware_bridge.py"

class TelemetryStub:
    def __init__(self, **kwargs):
        self.values = kwargs

def load_conversion():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8-sig"))
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name in {"_finite_telemetry_number", "_strict_telemetry_bool", "to_telemetry"}]
    assert len(functions) == 3
    namespace = {"TelemetryData": TelemetryStub}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace["to_telemetry"]

class RequiredSignedSafetyFields(unittest.TestCase):
    def setUp(self):
        self.convert = load_conversion()
        self.valid = {"emergency_brake_active": False, "driver_unwell": False}

    def test_explicit_safe_state_accepted(self):
        result = self.convert(self.valid)
        self.assertIs(result.values["emergency_brake_active"], False)
        self.assertIs(result.values["driver_unwell"], False)

    def test_missing_brake_state_rejected(self):
        with self.assertRaisesRegex(ValueError, "emergency_brake_active"):
            self.convert({"driver_unwell": False})

    def test_missing_driver_state_rejected(self):
        with self.assertRaisesRegex(ValueError, "driver_unwell"):
            self.convert({"emergency_brake_active": False})

    def test_ambiguous_boolean_rejected(self):
        with self.assertRaises(ValueError):
            self.convert({"emergency_brake_active": "false", "driver_unwell": False})

    def test_invalid_numeric_rejected(self):
        with self.assertRaises(ValueError):
            self.convert({**self.valid, "speed": float("nan")})

if __name__ == "__main__":
    unittest.main()
