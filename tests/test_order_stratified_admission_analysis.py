"""Regression controls for order-stratified exploratory bootstrap."""
import unittest

from research_contracts.analyze_paired_admission import summarize


def sample(first, memory=100, sqlite=200):
    return {"order": [first, "sqlite" if first == "memory" else "memory"],
            "memory_ns": [memory] * 3, "sqlite_ns": [sqlite] * 3}


class OrderStratifiedAnalysisTests(unittest.TestCase):
    def test_requires_both_randomization_orders(self):
        payload = {"schema": 1, "repeats": 2,
                   "samples": [sample("memory"), sample("memory")]}
        with self.assertRaisesRegex(ValueError, "both first-execution"):
            summarize(payload, resamples=100)

    def test_reproducible_and_preserves_stratum_counts(self):
        payload = {"schema": 1, "repeats": 5,
                   "samples": [sample("memory", sqlite=300),
                               sample("sqlite", sqlite=150),
                               sample("memory", sqlite=400),
                               sample("sqlite", sqlite=250),
                               sample("memory", sqlite=200)]}
        first = summarize(payload, resamples=300, seed=17)
        second = summarize(payload, resamples=300, seed=17)
        self.assertEqual(first, second)
        self.assertEqual(first["first_executed_order_strata"]["memory"]["trials"], 3)
        self.assertEqual(first["first_executed_order_strata"]["sqlite"]["trials"], 2)
        self.assertLessEqual(first["percentile_bootstrap_95_interval"][0],
                             first["geometric_mean_runtime_ratio"])
        self.assertGreaterEqual(first["percentile_bootstrap_95_interval"][1],
                                first["geometric_mean_runtime_ratio"])

    def test_rejects_invalid_duration(self):
        payload = {"schema": 1, "repeats": 2,
                   "samples": [sample("memory"), sample("sqlite", memory=0)]}
        with self.assertRaisesRegex(ValueError, "positive integer"):
            summarize(payload, resamples=100)


if __name__ == "__main__":
    unittest.main()
