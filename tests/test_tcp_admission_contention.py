"""Concurrency and monotonic-clock adversarial controls for production TCP admission.

This is a deterministic engineering experiment, not V2X detection evidence.
"""
import concurrent.futures
import threading
import unittest

from hardware_bridge import GlobalTelemetryBudget


class FrozenClock:
    def __init__(self):
        self.value = 100.0
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            return self.value

    def advance(self, delta):
        with self.lock:
            self.value += delta


class TCPAdmissionContentionExperiment(unittest.TestCase):
    def test_simultaneous_claims_never_exceed_burst(self):
        clock = FrozenClock()
        budget = GlobalTelemetryBudget(2, 7, clock=clock)
        gate = threading.Barrier(32)

        def claim(_):
            gate.wait(timeout=10)
            return budget.claim()

        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(claim, range(32)))
        self.assertEqual(sum(results), 7)
        self.assertEqual(len(results), 32)

    def test_refill_is_bounded_after_long_idle(self):
        clock = FrozenClock()
        budget = GlobalTelemetryBudget(3, 5, clock=clock)
        self.assertEqual(sum(budget.claim() for _ in range(20)), 5)
        clock.advance(1000)
        self.assertEqual(sum(budget.claim() for _ in range(20)), 5)

    def test_clock_regression_does_not_grant_tokens(self):
        clock = FrozenClock()
        budget = GlobalTelemetryBudget(1, 2, clock=clock)
        self.assertTrue(budget.claim())
        self.assertTrue(budget.claim())
        clock.advance(-500)
        self.assertFalse(budget.claim())

    def test_fractional_refill_and_saturation(self):
        clock = FrozenClock()
        budget = GlobalTelemetryBudget(2, 2, clock=clock)
        self.assertTrue(budget.claim())
        self.assertTrue(budget.claim())
        clock.advance(0.49)
        self.assertFalse(budget.claim())
        clock.advance(0.02)
        self.assertTrue(budget.claim())
        self.assertFalse(budget.claim())


if __name__ == "__main__":
    unittest.main()
