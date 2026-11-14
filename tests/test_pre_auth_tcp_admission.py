"""Synthetic admission-budget regression tests; not publishable DoS evidence."""
import unittest
from hardware_bridge import GlobalTelemetryBudget


class PreAuthenticationAdmissionTests(unittest.TestCase):
    def test_burst_exhaustion_and_refill(self):
        now = [100.0]
        bucket = GlobalTelemetryBudget(2, 3, clock=lambda: now[0])
        self.assertEqual([bucket.claim() for _ in range(4)], [True, True, True, False])
        now[0] += 0.5
        self.assertTrue(bucket.claim())
        self.assertFalse(bucket.claim())

    def test_reconnects_share_same_bucket(self):
        now = [100.0]
        shared = GlobalTelemetryBudget(1, 2, clock=lambda: now[0])
        self.assertTrue(shared.claim())   # first TCP accept
        self.assertTrue(shared.claim())   # second TCP accept
        self.assertFalse(shared.claim())  # reconnect refused

    def test_clock_rollback_does_not_refill(self):
        now = [100.0]
        bucket = GlobalTelemetryBudget(1, 1, clock=lambda: now[0])
        self.assertTrue(bucket.claim())
        now[0] = 90.0
        self.assertFalse(bucket.claim())


if __name__ == "__main__":
    unittest.main()
