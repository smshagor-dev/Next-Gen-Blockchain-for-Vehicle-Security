import unittest

from research_contracts.analyze_paired_admission import summarize


def sample(order, memory=(10, 20, 30), sqlite=(20, 40, 60)):
    return {"order": list(order), "memory_ns": list(memory), "sqlite_ns": list(sqlite)}


class PairedAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"schema": 1, "repeats": 4, "samples": [
            sample(("memory", "sqlite")), sample(("sqlite", "memory")),
            sample(("sqlite", "memory")), sample(("memory", "sqlite"))]}

    def test_exact_ratio_and_reproducible_interval(self):
        a = summarize(self.payload, resamples=100, seed=11)
        b = summarize(self.payload, resamples=100, seed=11)
        self.assertEqual(a, b)
        self.assertAlmostEqual(a["geometric_mean_runtime_ratio"], 2)
        self.assertEqual(a["percentile_bootstrap_95_interval"], [2, 2])
        self.assertEqual(a["first_executed_order_strata"]["memory"]["trials"], 2)

    def test_rejects_nonpositive_and_bool_durations(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value):
                data = {"schema": 1, "repeats": 2, "samples": [
                    sample(("memory", "sqlite"), memory=(value, 20, 30)),
                    sample(("sqlite", "memory"))]}
                with self.assertRaises(ValueError):
                    summarize(data, resamples=100)

    def test_rejects_malformed_or_missing_trials(self):
        for data in ({"schema": 2, "samples": []},
                     {"schema": 1, "repeats": 3, "samples": self.payload["samples"]},
                     {"schema": 1, "repeats": 2, "samples": [
                         sample(("memory", "memory")), sample(("sqlite", "memory"))]}):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    summarize(data, resamples=100)


if __name__ == "__main__":
    unittest.main()
