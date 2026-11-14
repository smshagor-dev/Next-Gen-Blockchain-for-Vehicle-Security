"""Executable concurrency and refill regressions for the production admission budget.

Uses the actual class from hardware_bridge, not a copied implementation.
No physical hardware is opened. These are engineering tests, not paper results.
"""
import concurrent.futures
import threading
import unittest

from hardware_bridge import GlobalTelemetryBudget


class FakeClock:
    def __init__(self):
        self.now = 100.0
    def __call__(self):
        return self.now


class GlobalBudgetConcurrencyTests(unittest.TestCase):
    def test_exact_burst_under_concurrent_claims(self):
        budget = GlobalTelemetryBudget(1, 7, clock=lambda: 100.0)
        barrier = threading.Barrier(32)
        def claim(_):
            barrier.wait(timeout=5)
            return budget.claim()
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(claim, range(32)))
        self.assertEqual(sum(results), 7)
        self.assertEqual(budget.tokens, 0.0)

    def test_refill_cannot_exceed_burst(self):
        clock = FakeClock()
        budget = GlobalTelemetryBudget(2, 3, clock=clock)
        self.assertEqual([budget.claim() for _ in range(4)], [True, True, True, False])
        clock.now += 100
        self.assertEqual([budget.claim() for _ in range(4)], [True, True, True, False])

    def test_backward_clock_does_not_refill(self):
        clock = FakeClock()
        budget = GlobalTelemetryBudget(1, 1, clock=clock)
        self.assertTrue(budget.claim())
        clock.now -= 20
        self.assertFalse(budget.claim())
        clock.now += 21
        self.assertTrue(budget.claim())


if __name__ == "__main__":
    unittest.main()
