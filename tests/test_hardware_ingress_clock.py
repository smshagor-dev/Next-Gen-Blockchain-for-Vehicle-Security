"""Synthetic receive-clock and delayed-commit contracts; not hardware evidence."""
import unittest
from datetime import datetime, timezone, timedelta
from hardware_ingress_clock import verify_ingress_observation

UTC = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)


class IngressClockTests(unittest.TestCase):
    def check(self, stamp="2026-11-15T11:59:50Z", **kw):
        return verify_ingress_observation(stamp, received_utc=UTC,
                                          received_monotonic=100.0,
                                          commit_monotonic=kw.pop("commit", 101.0), **kw)

    def test_recent_packet_accepted(self):
        result = self.check()
        self.assertEqual(result["age_at_ingress_seconds"], 10)
        self.assertEqual(result["age_at_commit_seconds"], 11)

    def test_exact_precommit_boundary(self):
        self.assertEqual(self.check(commit=105)["age_at_commit_seconds"], 15)

    def test_delayed_processing_rejects_previously_fresh_packet(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            self.check(commit=106)

    def test_stale_on_receive_cannot_be_refreshed(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            self.check("2026-11-15T11:59:44Z", commit=100)

    def test_future_timestamp_rejected_on_receive(self):
        with self.assertRaisesRegex(ValueError, "future"):
            self.check("2026-11-15T12:00:03Z", commit=100)

    def test_future_within_skew_can_pass(self):
        self.assertEqual(self.check("2026-11-15T12:00:02Z", commit=100)["age_at_ingress_seconds"], -2)

    def test_backwards_monotonic_time_rejected(self):
        with self.assertRaisesRegex(ValueError, "monotonic"):
            self.check(commit=99)

    def test_nonfinite_clock_rejected(self):
        for val in (float("nan"), float("inf"), float("-inf"), True):
            with self.subTest(val=val), self.assertRaises(ValueError):
                self.check(commit=val)

    def test_unbounded_queue_delay_rejected(self):
        with self.assertRaises(ValueError):
            self.check(commit=86501)

    def test_naive_utc_rejected(self):
        with self.assertRaises(ValueError):
            verify_ingress_observation("2026-11-15T12:00:00Z",
                                       received_utc=UTC.replace(tzinfo=None),
                                       received_monotonic=100, commit_monotonic=100)

    def test_non_utc_clock_rejected(self):
        with self.assertRaises(ValueError):
            verify_ingress_observation("2026-11-15T12:00:00Z",
                                       received_utc=UTC.astimezone(timezone(timedelta(hours=1))),
                                       received_monotonic=100, commit_monotonic=100)

    def test_policy_threshold_is_forwarded(self):
        self.assertEqual(self.check(commit=120, max_age_seconds=30)["age_at_commit_seconds"], 30)
        with self.assertRaises(ValueError):
            self.check(commit=120, max_age_seconds=15)

    def test_invalid_signed_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            self.check("2026-11-15T12:00:00")

    def test_no_host_clock_override_by_sender(self):
        with self.assertRaises(ValueError):
            self.check("2026-11-15T12:00:04Z")


if __name__ == "__main__":
    unittest.main()
