import unittest

from experiments.claim_validation.consensus_probe import trial
from experiments.claim_validation.performance_probe import (
    prepare, freshness_rows, summarize_freshness, benchmark, summarize_timing, METHODS,
)


class PerformanceProbeTests(unittest.TestCase):
    def setUp(self):
        self.prepared = [prepare("consensus", trial(0, 0, allowed)) for allowed in (True, False)]

    def test_freshness_inclusive_boundary(self):
        rows = list(freshness_rows("consensus", self.prepared))
        for age, eligible in ((-1, False), (0, True), (1, True), (10, False)):
            row = next(r for r in rows if r["reference_positive"] and r["threshold_ms"] == 1
                       and r["synthetic_age_ms"] == age)
            self.assertEqual(row["eligibility"] == "ELIGIBLE", eligible)

    def test_negative_not_eligible(self):
        rows = list(freshness_rows("consensus", self.prepared))
        self.assertFalse(any(not r["reference_positive"] and r["eligibility"] == "ELIGIBLE" for r in rows))
        self.assertEqual(len(rows), 80)
        self.assertEqual(len(summarize_freshness(rows)), 40)

    def test_balanced_randomized_timing_blocks(self):
        rows = benchmark("consensus", self.prepared, blocks=3, passes=2)
        self.assertEqual(len(rows), 9)
        for block in range(3):
            subset = [r for r in rows if r["block"] == block]
            self.assertEqual({r["method"] for r in subset}, set(METHODS))
            self.assertEqual({r["calls"] for r in subset}, {4})
            self.assertTrue(all(r["elapsed_ns"] > 0 for r in subset))
        summary = summarize_timing(rows)
        self.assertEqual(summary["observed_gate"]["calls"], 12)


if __name__ == "__main__":
    unittest.main()
