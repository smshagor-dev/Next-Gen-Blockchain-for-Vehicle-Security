"""Regression: blocking remote commands must not retain the chain mutation lock."""
import ast
from pathlib import Path
import unittest


class PiLockIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).resolve().parents[1].joinpath("hardware_bridge.py").read_text(encoding="utf-8-sig")
        cls.tree = ast.parse(cls.source)

    def test_pi_chain_lock_excludes_network_actuation(self):
        run = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_pi_mode")
        handler = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "handle_client")
        locks = [n for n in ast.walk(handler) if isinstance(n, ast.With)]
        chain = [n for n in locks if any(isinstance(i.context_expr, ast.Name) and i.context_expr.id == "ledger_lock" for i in n.items)]
        actuator = [n for n in locks if any(isinstance(i.context_expr, ast.Name) and i.context_expr.id == "actuator_lock" for i in n.items)]
        self.assertEqual(len(chain), 1)
        self.assertEqual(len(actuator), 1)
        chain_calls = [n.func.attr for n in ast.walk(chain[0]) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        self.assertIn("push_telemetry", chain_calls)
        self.assertNotIn("maybe_send_pi", chain_calls)
        actuator_calls = [n.func.attr for n in ast.walk(actuator[0]) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        self.assertIn("maybe_send_pi", actuator_calls)
        self.assertLess(chain[0].end_lineno, actuator[0].lineno)

    def test_pi_handler_has_separate_locks(self):
        run = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_pi_mode")
        assigned = {target.id for n in run.body if isinstance(n, ast.Assign) for target in n.targets if isinstance(target, ast.Name)}
        self.assertTrue({"ledger_lock", "actuator_lock"}.issubset(assigned))


if __name__ == "__main__":
    unittest.main()
