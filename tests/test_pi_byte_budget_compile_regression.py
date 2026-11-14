"""Regression for byte-budget code parsing and per-connection accounting.

This is a source-level guard, not a network or DoS performance experiment.
"""
import ast
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "hardware_bridge.py"


class PiSessionByteBudgetCompilationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(SOURCE.read_text(encoding="utf-8-sig"), filename=str(SOURCE))

    def test_bridge_compiles_without_importing_hardware(self):
        compile(SOURCE.read_text(encoding="utf-8-sig"), str(SOURCE), "exec")

    def test_session_counter_initialized_and_incremented_before_limit(self):
        runner = next(
            node for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "run_pi_mode"
        )
        handler = next(
            node for node in runner.body
            if isinstance(node, ast.FunctionDef) and node.name == "handle_client"
        )
        init = [
            node for node in ast.walk(handler)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "received_bytes" for t in node.targets)
            and isinstance(node.value, ast.Constant) and node.value.value == 0
        ]
        increments = [
            node for node in ast.walk(handler)
            if isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name) and node.target.id == "received_bytes"
            and isinstance(node.op, ast.Add)
        ]
        guards = [
            node for node in ast.walk(handler)
            if isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name) and node.left.id == "received_bytes"
            and any(isinstance(c, ast.Name) and c.id == "max_session_bytes" for c in node.comparators)
        ]
        self.assertEqual(len(init), 1)
        self.assertEqual(len(increments), 1)
        self.assertEqual(len(guards), 1)
        self.assertLess(init[0].lineno, increments[0].lineno)
        self.assertLess(increments[0].lineno, guards[0].lineno)


if __name__ == "__main__":
    unittest.main()
