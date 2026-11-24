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
        self.assertIn("SMARTCAR_HW_SERIAL_MAX_FRAMES_PER_SESSION", self.src)
        self.assertIn("max_frames=max(1, min(10000,", self.src)
        self.assertIn("serial_budget.charge_frame()", self.src)
        self.assertIn("remaining_frames=serial_budget.max_frames - serial_budget.frames_seen", self.src)

    def test_byte_budget_configured_and_bounded(self):
        self.assertIn("SMARTCAR_HW_SERIAL_MAX_SESSION_BYTES", self.src)
        self.assertIn("max_bytes=max(1024, min(8 * 1024 * 1024,", self.src)
        self.assertIn("serial_budget.charge_bytes(len(chunk))", self.src)

    def test_bytes_charged_before_frame_verification(self):
        self.assertLess(self.src.index("serial_budget.charge_bytes(len(chunk))"),
                        self.src.index("_quarantined_serial_frames("))

    def test_frames_charged_before_ledger_write(self):
        self.assertLess(self.src.index("serial_budget.charge_frame()"),
                        self.src.index("block = bc.push_telemetry(tel, event)"))

    def test_budget_failure_closes_serial_and_nonce_store(self):
        self.assertIn("except SerialIngressBudgetExceeded", self.src)
        self.assertIn("port quarantined", self.src)
        self.assertIn("ser.close()", self.src)
        self.assertIn("nonce_store.close()", self.src)

    def test_local_emergency_control_remains_unmodified(self):
        self.assertNotIn("send_safe_mode_stop(", self.src)
        self.assertNotIn("SMARTCAR_ECU_CONTROL_ENABLED", self.src)


if __name__ == "__main__":
    unittest.main()
