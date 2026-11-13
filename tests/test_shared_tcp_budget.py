"""Concurrent token-budget regression; no network or actuation required."""
import ast
import pathlib
import threading
import time
import unittest

# Isolate the pure budget class to avoid optional hardware/chain imports.
source = pathlib.Path(__file__).resolve().parents[1] / "hardware_bridge.py"
module = ast.parse(source.read_text(encoding="utf-8-sig"))
node = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == "GlobalTelemetryBudget")
namespace = {"time": time, "threading": threading}
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
GlobalTelemetryBudget = namespace["GlobalTelemetryBudget"]

class SharedBudgetTests(unittest.TestCase):
    def test_concurrent_claims_never_exceed_burst(self):
        budget = GlobalTelemetryBudget(1, 7, clock=lambda: 0.0)
        barrier = threading.Barrier(32)
        results = []
        result_lock = threading.Lock()
        def worker():
            barrier.wait(timeout=5)
            granted = budget.claim()
            with result_lock:
                results.append(granted)
        threads = [threading.Thread(target=worker) for _ in range(32)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(len(results), 32)
        self.assertEqual(sum(results), 7)
        self.assertEqual(budget.tokens, 0.0)

    def test_refill_is_atomic_with_claim(self):
        tick = [0.0]
        budget = GlobalTelemetryBudget(2, 3, clock=lambda: tick[0])
        self.assertEqual(sum(budget.claim() for _ in range(4)), 3)
        tick[0] = 1.0
        self.assertEqual(sum(budget.claim() for _ in range(10)), 2)

if __name__ == "__main__":
    unittest.main()
