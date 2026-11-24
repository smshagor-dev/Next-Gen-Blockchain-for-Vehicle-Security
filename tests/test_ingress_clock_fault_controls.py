"""Non-actuating adversarial host-clock and queue-delay controls.

Run: python -m unittest discover -s tests -p 'test_ingress_clock_fault_controls.py' -v
"""
import unittest
from datetime import datetime, timezone
from hardware_ingress_clock import verify_ingress_observation


class IngressClockFaultControls(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc)
        self.signed = "2026-11-23T09:59:50Z"

    def check(self, **changes):
        args = dict(timestamp=self.signed, received_utc=self.now,
                    received_monotonic=100.0, commit_monotonic=100.0,
                    max_age_seconds=15, max_future_skew_seconds=2)
        args.update(changes)
        return verify_ingress_observation(**args)

    def test_delayed_commit_cannot_refresh_signed_observation(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            self.check(commit_monotonic=106.0)

    def test_monotonic_rollback_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "monotonic"):
            self.check(commit_monotonic=99.0)

    def test_future_signed_observation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "future"):
            self.check(timestamp="2026-11-23T10:00:03Z")

    def test_valid_boundary_and_elapsed_are_reported(self):
        result = self.check(commit_monotonic=105.0)
        self.assertAlmostEqual(result["age_at_ingress_seconds"], 10.0)
        self.assertAlmostEqual(result["age_at_commit_seconds"], 15.0)

    def test_host_datetime_overflow_fails_closed_as_value_error(self):
        near_max = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "overflow"):
            self.check(received_utc=near_max,
                       timestamp="9999-12-31T23:59:59Z",
                       commit_monotonic=102.0)

    def test_excessive_queue_delay_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "delay"):
            self.check(commit_monotonic=86501.0)


if __name__ == "__main__":
    unittest.main()
