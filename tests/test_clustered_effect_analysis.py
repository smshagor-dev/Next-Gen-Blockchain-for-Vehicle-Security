"""Synthetic contract tests, not publishable experiments."""
import csv
import tempfile
import unittest
from pathlib import Path
from experiments.v2x.clustered_effect_analysis import analyze

class ClusteredEffectTests(unittest.TestCase):
    def run_rows(self, rows, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incidents.csv"
            with path.open("w", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["incident_id", "cluster_id", "truth", "baseline", "candidate"])
                writer.writerows(rows)
            return analyze(path, **kwargs)

    def test_deterministic(self):
        rows = [("a", "one", 1, 0, 1), ("b", "one", 0, 0, 0), ("c", "two", 1, 1, 0)]
        self.assertEqual(self.run_rows(rows, repetitions=200), self.run_rows(rows, repetitions=200))
        self.assertEqual(self.run_rows(rows)["estimate_pp"], 0)

    def test_uniform_improvement(self):
        result = self.run_rows([("a", "one", 1, 0, 1), ("b", "two", 0, 1, 0)])
        self.assertEqual(result["cluster_bootstrap_percentile_ci_pp"], [100, 100])

    def test_single_cluster_rejected(self):
        with self.assertRaises(ValueError):
            self.run_rows([("a", "one", 1, 1, 1)])

    def test_duplicate_incident_rejected(self):
        with self.assertRaises(ValueError):
            self.run_rows([("a", "one", 1, 1, 1), ("a", "two", 1, 0, 1)])

    def test_invalid_binary_rejected(self):
        with self.assertRaises(ValueError):
            self.run_rows([("a", "one", 2, 1, 1), ("b", "two", 1, 0, 1)])

    def test_invalid_schema_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text("incident_id,truth\na,1\n")
            with self.assertRaises(ValueError):
                analyze(path)
