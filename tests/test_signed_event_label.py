"""Executable signed event-label admission tests without hardware imports."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "hardware_bridge.py"


def load_validator():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8-sig"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_signed_event_label"]
    if len(functions) != 1:
        raise AssertionError("expected exactly one event validator")
    scope = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), "exec"), scope)
    return scope["_signed_event_label"], tree


class SignedEventLabelTests(unittest.TestCase):
    def test_valid_label(self):
        validate, _ = load_validator()
        self.assertEqual(validate("collision_warning"), "collision_warning")

    def test_ambiguous_or_missing_labels_rejected(self):
        validate, _ = load_validator()
        for value in (None, 0, False, [], {}, "", "x" * 161):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value)

    def test_multibyte_utf8_budget(self):
        validate, _ = load_validator()
        self.assertEqual(validate("é" * 80), "é" * 80)
        with self.assertRaises(ValueError):
            validate("é" * 81)

    def test_control_characters_rejected(self):
        validate, _ = load_validator()
        for value in ("ok\\nforged", "ok\\x00", "ok\\x7f"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value)

    def test_no_legacy_event_coercion_at_ledger_boundary(self):
        _, tree = load_validator()
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "push_telemetry"]
        self.assertGreaterEqual(len(calls), 2)
        text = SOURCE.read_text(encoding="utf-8-sig")
        self.assertNotIn('str(item.payload["event"])', text)
        self.assertGreaterEqual(text.count('_signed_event_label(item.payload.get("event"))'), 2)


if __name__ == "__main__":
    unittest.main()
