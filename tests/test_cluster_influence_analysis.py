"""Synthetic contracts; these are not publishable V2X observations."""
import csv
import tempfile
import unittest
from pathlib import Path
from experiments.v2x.cluster_influence_analysis import analyze

class ClusterInfluenceTests(unittest.TestCase):
    def evaluate(self, rows, header=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incidents.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(header or ["incident_id", "cluster_id", "truth", "baseline", "candidate"])
                writer.writerows(rows)
            return analyze(path)

    def test_one_cluster_can_reverse_result(self):
        rows = [["a1", "A", "1", "0", "1"], ["a2", "A", "1", "0", "1"],
                ["b", "B", "1", "1", "0"], ["c", "C", "1", "1", "1"]]
        result = self.evaluate(rows)
        self.assertEqual(result["full_estimate_pp"], 25)
        self.assertTrue(result["sign_reversal_under_omission"])
        self.assertEqual(result["minimum_loo_pp"], -50)

    def test_null_crossing_is_not_sign_reversal(self):
        rows = [["a", "A", "1", "0", "1"],
                ["b", "B", "1", "1", "1"],
                ["c", "C", "1", "1", "1"]]
        result = self.evaluate(rows)
        self.assertFalse(result["sign_reversal_under_omission"])
        self.assertTrue(result["reaches_null_under_omission"])

    def test_negative_to_positive_is_strict_reversal(self):
        rows = [["a1", "A", "1", "1", "0"],
                ["a2", "A", "1", "1", "0"],
                ["b", "B", "1", "0", "1"],
                ["c", "C", "1", "1", "1"]]
        result = self.evaluate(rows)
        self.assertTrue(result["sign_reversal_under_omission"])
        self.assertFalse(result["reaches_null_under_omission"])

    def test_uniform_improvement(self):
        result = self.evaluate([[str(i), str(i), "1", "0", "1"] for i in range(3)])
        self.assertEqual(result["minimum_loo_pp"], 100)
        self.assertFalse(result["sign_reversal_under_omission"])

    def test_duplicate_incident_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.evaluate([["a","A","1","0","1"], ["a","B","1","0","1"], ["c","C","1","0","1"]])

    def test_fewer_than_three_clusters_rejected(self):
        with self.assertRaisesRegex(ValueError, "three"):
            self.evaluate([["a","A","1","0","1"], ["b","B","1","0","1"]])

    def test_invalid_binary_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonbinary"):
            self.evaluate([["a","A","1","2","1"], ["b","B","1","0","1"], ["c","C","1","0","1"]])

    def test_extra_column_rejected(self):
        with self.assertRaisesRegex(ValueError, "schema"):
            self.evaluate([["a","A","1","0","1","x"]], ["incident_id","cluster_id","truth","baseline","candidate","extra"])

if __name__ == "__main__":
    unittest.main()
