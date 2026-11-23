"""Non-actuating deterministic quota clock fault tests."""
import unittest
from hardware_bridge import GlobalTelemetryBudget


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class BudgetClockTests(unittest.TestCase):
    def test_rollback_does_not_mint_quota(self):
        clock = Clock()
        budget = GlobalTelemetryBudget(1, 1, clock=clock)
        self.assertTrue(budget.claim())
        clock.now = 90.0
        self.assertFalse(budget.claim())
        clock.now = 100.0
        self.assertFalse(budget.claim())
        clock.now = 101.0
        self.assertTrue(budget.claim())

    def test_nonfinite_clock_rejected(self):
        clock = Clock()
        budget = GlobalTelemetryBudget(1, 1, clock=clock)
        self.assertTrue(budget.claim())
        for value in (float("nan"), float("inf"), -float("inf")):
            clock.now = value
            self.assertFalse(budget.claim())
        clock.now = 101.0
        self.assertTrue(budget.claim())

    def test_normal_refill_remains_bounded(self):
        clock = Clock()
        budget = GlobalTelemetryBudget(2, 2, clock=clock)
        self.assertTrue(budget.claim())
        self.assertTrue(budget.claim())
        self.assertFalse(budget.claim())
        clock.now = 100.5
        self.assertTrue(budget.claim())
        self.assertFalse(budget.claim())


if __name__ == "__main__":
    unittest.main()
