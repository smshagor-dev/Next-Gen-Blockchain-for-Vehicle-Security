"""Deterministic aggregate telemetry rate budget regression tests."""
import unittest
from hardware_bridge import GlobalTelemetryBudget


class GlobalBudgetTests(unittest.TestCase):
    def test_burst_exhaustion_and_refill(self):
        ticks = [0.0]
        budget = GlobalTelemetryBudget(2, 3, clock=lambda: ticks[0])
        self.assertEqual([budget.claim() for _ in range(4)], [True, True, True, False])
        ticks[0] = 0.5
        self.assertTrue(budget.claim())
        self.assertFalse(budget.claim())
        ticks[0] = 2.0
        self.assertEqual([budget.claim() for _ in range(4)], [True, True, True, False])

    def test_quota_is_shared_between_clients(self):
        ticks = [0.0]
        shared = GlobalTelemetryBudget(1, 1, clock=lambda: ticks[0])
        self.assertTrue(shared.claim())  # first connection
        self.assertFalse(shared.claim())  # new connection, same server
        ticks[0] = 1.0
        self.assertTrue(shared.claim())

    def test_clock_rollback_never_refills(self):
        ticks = [10.0]
        budget = GlobalTelemetryBudget(1, 1, clock=lambda: ticks[0])
        self.assertTrue(budget.claim())
        ticks[0] = 9.0
        self.assertFalse(budget.claim())

    def test_invalid_configuration_is_bounded(self):
        budget = GlobalTelemetryBudget(0, 999999)
        self.assertEqual(budget.rate, 1)
        self.assertEqual(budget.burst, 10000)


if __name__ == "__main__":
    unittest.main()
