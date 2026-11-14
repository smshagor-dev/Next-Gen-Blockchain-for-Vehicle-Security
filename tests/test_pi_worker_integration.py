"""Source-level integration guard for bounded production Pi ingress.

This does not replace live socket tests or hardware safety validation.
"""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT.joinpath("hardware_bridge.py").read_text(encoding="utf-8-sig")


class ProductionPiIntegrationTests(unittest.TestCase):
    def test_source_parses_and_uses_bounded_workers(self):
        tree = ast.parse(SOURCE)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_pi_mode")
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)]
        self.assertTrue(any(isinstance(c.func, ast.Name) and c.func.id == "BoundedTCPAdmission" for c in calls))
        self.assertTrue(any(isinstance(c.func, ast.Attribute) and c.func.attr == "dispatch" for c in calls))
        self.assertTrue(any(isinstance(n, ast.With) and any(isinstance(item.context_expr, ast.Name) and item.context_expr.id == "verifier_lock" for item in n.items) for n in ast.walk(function)))
        self.assertTrue(any(isinstance(n, ast.With) and any(isinstance(item.context_expr, ast.Name) and item.context_expr.id == "ledger_lock" for item in n.items) for n in ast.walk(function)))

    def test_no_unbounded_thread_per_connection(self):
        function = next(n for n in ast.parse(SOURCE).body if isinstance(n, ast.FunctionDef) and n.name == "run_pi_mode")
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "Thread" for n in ast.walk(function)))


if __name__ == "__main__":
    unittest.main()
