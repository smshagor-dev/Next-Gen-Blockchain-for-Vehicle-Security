"""Negative-control tests for adversarial paired benchmark JSON (stdlib only)."""
import unittest

from research_contracts.analyze_paired_admission import summarize


def payload(memory=100, sqlite=200):
    return {"schema": 1, "repeats": 2, "samples": [
        {"order": ["memory", "sqlite"], "memory_ns": [memory] * 3, "sqlite_ns": [sqlite] * 3},
        {"order": ["sqlite", "memory"], "memory_ns": [memory] * 3, "sqlite_ns": [sqlite] * 3},
    ]}


class NumericEvidenceIntegrityTests(unittest.TestCase):
    def test_normal_paired_ratio(self):
        self.assertAlmostEqual(summarize(payload(), resamples=100)["geometric_mean_runtime_ratio"], 2)

    def test_bool_schema_rejected(self):
        item = payload()
        item["schema"] = True
        with self.assertRaises(ValueError):
            summarize(item, resamples=100)

    def test_bool_repeats_rejected(self):
        item = payload()
        item["repeats"] = True
        with self.assertRaises(ValueError):
            summarize(item, resamples=100)

    def test_huge_valid_integer_durations_do_not_overflow(self):
        self.assertAlmostEqual(
            summarize(payload(10**400, 2 * 10**400), resamples=100)["geometric_mean_runtime_ratio"], 2
        )

    def test_extreme_ratio_fails_closed(self):
        with self.assertRaises(ValueError):
            summarize(payload(1, 10**400), resamples=100)


if __name__ == "__main__":
    unittest.main()
