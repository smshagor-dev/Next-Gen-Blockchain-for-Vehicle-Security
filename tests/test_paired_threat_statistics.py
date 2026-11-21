"""Contract tests for paired threat statistics; synthetic fixtures only."""
import unittest
from research_contracts.paired_threat_statistics import summarize


def rows():
    result = []
    for seed in range(4):
        for incident in range(10):
            truth = incident % 2
            for policy in ("authentication_only", "dissent_tolerant_groups"):
                error = int(policy == "authentication_only" and incident % 3 == 0)
                result.append(dict(seed=seed, incident=incident, policy=policy,
                                   truth_hazard=truth, observed_bits="0101",
                                   false_admission=error if not truth else 0,
                                   missed_hazard=error if truth else 0))
    return result


class ClusterBootstrapTests(unittest.TestCase):
    def test_reproducible(self):
        a = summarize(rows(), "authentication_only", "dissent_tolerant_groups", draws=200, seed=7)
        self.assertEqual(a, summarize(rows(), "authentication_only", "dissent_tolerant_groups", draws=200, seed=7))
        self.assertEqual(a["seeds"], 4)
        self.assertLess(a["risk_difference"], 0)

    def test_missing_pair_rejected(self):
        with self.assertRaises(ValueError):
            summarize(rows()[:-1], "authentication_only", "dissent_tolerant_groups")

    def test_mismatched_truth_rejected(self):
        data = rows()
        data[1]["truth_hazard"] = 1
        with self.assertRaises(ValueError):
            summarize(data, "authentication_only", "dissent_tolerant_groups")

    def test_single_seed_rejected(self):
        with self.assertRaises(ValueError):
            summarize([r for r in rows() if r["seed"] == 0], "authentication_only", "dissent_tolerant_groups")

    def test_duplicate_pair_rejected(self):
        data = rows()
        data.append(dict(data[0]))
        with self.assertRaises(ValueError):
            summarize(data, "authentication_only", "dissent_tolerant_groups")


if __name__ == "__main__":
    unittest.main()
