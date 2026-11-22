"""Regression contract for Arduino serial admission budgets (source-level guard).

These tests check that the production ingress contains independent session
byte/frame limits and that each limit precedes ledger mutation. They are NOT
substitutes for live serial fault-injection or an end-to-end hardware test.
"""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "hardware_bridge.py"


class ArduinoBudgetContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(SOURCE.read_text(encoding="utf-8-sig"))
        cls.fn = next(n for n in cls.tree.body if isinstance(n, ast.FunctionDef)
                      and n.name == "run_arduino_mode")
        cls.src = ast.get_source_segment(SOURCE.read_text(encoding="utf-8-sig"), cls.fn)
        # Use AST structure instead of brittle whole-file text matching.
        cls.calls = [n for n in ast.walk(cls.fn) if isinstance(n, ast.Call)]

    def test_frame_budget_configured_and_bounded(self):
        self.assertIn("SMARTCAR_HW_MAX_FRAMES_PER_SESSION", self.src)
        self.assertIn("accepted_frames > max_frames", self.src)

    def test_byte_budget_configured_and_bounded(self):
        self.assertIn("SMARTCAR_HW_MAX_SESSION_BYTES", self.src)
        self.assertIn("received_bytes > max_session_bytes", self.src)

    def test_bytes_charged_before_frame_verification(self):
        self.assertLess(self.src.index("received_bytes += len(chunk)"),
                        self.src.index("verified = session.receive_iter(chunk)"))

    def test_frames_charged_before_ledger_write(self):
        self.assertLess(self.src.index("accepted_frames += 1"),
                        self.src.index("block = bc.push_telemetry(tel, event)"))

    def test_local_emergency_control_remains_unmodified(self):
        self.assertNotIn("send_safe_mode_stop(", self.src)
        self.assertNotIn("SMARTCAR_ECU_CONTROL_ENABLED", self.src)


if __name__ == "__main__":
    unittest.main()
