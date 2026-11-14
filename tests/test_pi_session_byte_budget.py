"""Regression guards for per-session TCP byte accounting (no hardware required)."""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PiSessionByteBudgetTests(unittest.TestCase):
    def test_byte_budget_is_checked_before_verification(self):
        tree = ast.parse((ROOT / "hardware_bridge.py").read_text(encoding="utf-8-sig"))
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_pi_mode")
        handler = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "handle_client")
        source = ast.get_source_segment((ROOT / "hardware_bridge.py").read_text(encoding="utf-8-sig"), handler)
        self.assertIsNotNone(source)
        self.assertIn("received_bytes += len(data)", source)
        self.assertIn("received_bytes > max_session_bytes", source)
        self.assertIn("HW_SESSION_BYTE_BUDGET_EXCEEDED", source)
        self.assertLess(source.index("received_bytes > max_session_bytes"), source.index("session.receive(data)"))

    def test_budget_is_configurable_and_capped(self):
        text = (ROOT / "hardware_bridge.py").read_text(encoding="utf-8-sig")
        self.assertIn('get_int("SMARTCAR_HW_MAX_SESSION_BYTES", 262144)', text)
        self.assertIn("8 * 1024 * 1024", text)


if __name__ == "__main__":
    unittest.main()
