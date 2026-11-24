import unittest
from research_contracts.cluster_signflip import paired_cluster_test


class ClusterSignflipTests(unittest.TestCase):
    def test_exact_two_clusters(self):
        self.assertEqual(paired_cluster_test([("a", "1", 0, 1), ("b", "2", 0, 1)])["two_sided_p_value"], 0.5)

    def test_equal_cluster_weight(self):
        rows = [("a", str(i), 0, 1) for i in range(100)] + [("b", "b", 1, 0)]
        self.assertEqual(paired_cluster_test(rows)["cluster_equal_weight_mean_difference"], 0)

    def test_duplicate_incident_rejected(self):
        with self.assertRaises(ValueError):
            paired_cluster_test([("a", "x", 0, 1), ("b", "x", 0, 1)])

    def test_nan_rejected(self):
        with self.assertRaises(ValueError):
            paired_cluster_test([("a", "x", 0, float("nan")), ("b", "y", 0, 1)])

    def test_monte_carlo_reproducible(self):
        rows = [(str(i), str(i), 0, 1) for i in range(17)]
        a = paired_cluster_test(rows, seed=3, permutations=199)
        self.assertEqual(a, paired_cluster_test(rows, seed=3, permutations=199))
        self.assertGreater(a["two_sided_p_value"], 0)

    def test_single_cluster_rejected(self):
        with self.assertRaises(ValueError):
            paired_cluster_test([("a", "x", 0, 1)])


if __name__ == "__main__":
    unittest.main()
