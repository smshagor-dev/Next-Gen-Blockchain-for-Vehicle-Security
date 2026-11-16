"""Synthetic timestamp-policy contracts, not hardware or publication evidence."""
import unittest
from datetime import datetime, timedelta, timezone
from hardware_observation_freshness import verify_observation_age

NOW = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)

class ObservationFreshnessTests(unittest.TestCase):
    def check(self, timestamp, **kwargs):
        return verify_observation_age(timestamp, received_utc=NOW, **kwargs)

    def test_recent_signed_timestamp(self):
        self.assertEqual(self.check("2026-11-15T11:59:50Z"), 10.0)

    def test_exact_stale_boundary_is_accepted(self):
        self.assertEqual(self.check("2026-11-15T11:59:45+00:00"), 15.0)

    def test_stale_payload_with_fresh_envelope_must_fail(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            self.check("2026-11-15T11:59:44Z")

    def test_exact_future_boundary_is_accepted(self):
        self.assertEqual(self.check("2026-11-15T12:00:02Z"), -2.0)

    def test_future_dated_payload_rejected(self):
        with self.assertRaisesRegex(ValueError, "future"):
            self.check("2026-11-15T12:00:02.000001Z")

    def test_missing_or_noncanonical_timestamp(self):
        for value in (None, "", 123, "2026-11-15T12:00:00", "2026-11-15T13:00:00+01:00",
                      "2026-11-15T12:00Z", "2026-11-15T12:00:00z",
                      "2026-11-15T12:00:00,1Z", "a" * 100):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(value)

    def test_naive_host_clock_rejected(self):
        with self.assertRaisesRegex(ValueError, "host reception"):
            verify_observation_age("2026-11-15T12:00:00Z",
                                   received_utc=NOW.replace(tzinfo=None))

    def test_non_utc_host_clock_rejected(self):
        with self.assertRaisesRegex(ValueError, "host reception"):
            verify_observation_age("2026-11-15T12:00:00Z",
                                   received_utc=NOW.astimezone(timezone(timedelta(hours=1))))

    def test_policy_bounds_rejected(self):
        for age, skew in ((0, 2), (3601, 2), (15, -1), (15, 61),
                          (True, 2), (15, False), ("15", 2)):
            with self.subTest(age=age, skew=skew), self.assertRaises(ValueError):
                self.check("2026-11-15T12:00:00Z",
                           max_age_seconds=age, max_future_skew_seconds=skew)

    def test_configured_age_changes_decision(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            self.check("2026-11-15T11:59:30Z", max_age_seconds=15)
        self.assertEqual(self.check("2026-11-15T11:59:30Z", max_age_seconds=30), 30.0)

    def test_fractional_timestamp(self):
        self.assertEqual(self.check("2026-11-15T11:59:59.500000Z"), 0.5)

    def test_invalid_calendar_date(self):
        with self.assertRaises(ValueError):
            self.check("2026-02-30T12:00:00Z")

if __name__ == "__main__":
    unittest.main()
