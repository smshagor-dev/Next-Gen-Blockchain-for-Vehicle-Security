import unittest
from experiments.v2x.scenario_cluster_bootstrap import compare_clustered


class ClusterTests(unittest.TestCase):
    def test_deterministic_and_paired(self):
        rows = [((f"s{i}", f"e{j}"), j % 2, j % 2, 1 - j % 2)
                for i in range(8) for j in range(4)]
        a = compare_clustered(rows, replicates=100)
        self.assertEqual(a, compare_clustered(rows, replicates=100))
        self.assertEqual(a["effect"], -1.0)
        self.assertEqual(a["ci95"], [-1.0, -1.0])

    def test_single_cluster_refused(self):
        rows = [(("s", "a"), 0, 0, 0), (("s", "b"), 1, 1, 1)]
        self.assertEqual(compare_clustered(rows)["status"], "insufficient_independent_scenarios")

    def test_class_loss_not_hidden(self):
        rows = [(("a", "1"), 0, 0, 0), (("b", "1"), 1, 1, 1)]
        result = compare_clustered(rows, replicates=100)
        self.assertEqual(result["status"], "unstable_class_support_under_cluster_resampling")
        self.assertIsNone(result["ci95"])

    def test_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            compare_clustered([(("a", "1"), 0, 0, 0)] * 2)

    def test_bool_rejected(self):
        with self.assertRaises(ValueError):
            compare_clustered([(("a", "1"), True, 0, 0), (("b", "2"), 0, 0, 0)])


if __name__ == "__main__":
    unittest.main()
