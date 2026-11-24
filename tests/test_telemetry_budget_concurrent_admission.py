"""Concurrent quota admission experiment: software-only, no vehicle commands.

Tests the actual shared GlobalTelemetryBudget implementation under simultaneous
authenticated-admission claims. This is a synchronization invariant check, NOT
independent V2X detection evidence or a statistical significance test.
"""
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from hardware_bridge import GlobalTelemetryBudget


class TelemetryBudgetConcurrentAdmission(unittest.TestCase):
    def test_one_burst_is_not_multiplied_by_concurrent_clients(self):
        clients, burst = 64, 7
        budget = GlobalTelemetryBudget(rate_per_sec=1, burst=burst, clock=lambda: 100.0)
        barrier = threading.Barrier(clients)
        def attempt(_):
            barrier.wait(timeout=10)
            return budget.claim()
        with ThreadPoolExecutor(max_workers=clients) as pool:
            admitted = list(pool.map(attempt, range(clients)))
        self.assertEqual(sum(admitted), burst)
        self.assertEqual(len(admitted), clients)

    def test_concurrent_refill_does_not_overallocate(self):
        clients, burst = 32, 3
        now = [100.0]
        budget = GlobalTelemetryBudget(rate_per_sec=2, burst=burst, clock=lambda: now[0])
        self.assertEqual(sum(budget.claim() for _ in range(burst)), burst)
        now[0] = 101.0
        barrier = threading.Barrier(clients)
        def attempt(_):
            barrier.wait(timeout=10)
            return budget.claim()
        with ThreadPoolExecutor(max_workers=clients) as pool:
            admitted = list(pool.map(attempt, range(clients)))
        self.assertEqual(sum(admitted), 2)

    def test_no_cross_session_refill_when_time_frozen(self):
        budget = GlobalTelemetryBudget(rate_per_sec=10000, burst=1, clock=lambda: 42.0)
        self.assertTrue(budget.claim())
        for _ in range(1000):
            self.assertFalse(budget.claim())


if __name__ == "__main__":
    unittest.main()
