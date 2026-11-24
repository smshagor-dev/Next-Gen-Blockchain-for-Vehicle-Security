"""Regression controls for incident-level evaluation; no synthetic efficacy claims."""
import csv
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "research_contracts"))
from incident_paired_evaluation import load_incidents, evaluate


class IncidentEvaluationTests(unittest.TestCase):
    def write_rows(self, rows):
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", newline="", delete=False)
        with handle:
            writer = csv.writer(handle)
            writer.writerow(["incident_id", "split", "label", "baseline_score", "proposed_score"])
            writer.writerows(rows)
        self.addCleanup(lambda: os.unlink(handle.name))
        return handle.name

    def test_repeated_frames_count_as_one_incident(self):
        path = self.write_rows([
            ["a", "test", 1, .1, .9], ["a", "test", 1, .8, .9],
            ["b", "test", 0, .1, .1]])
        result = evaluate(load_incidents(path), replicates=100)
        self.assertEqual(result["test_incidents"], 2)
        self.assertEqual(result["paired_difference"], 0)

    def test_split_leakage_rejected(self):
        path = self.write_rows([["a", "train", 1, .1, .9],
                                ["a", "test", 1, .1, .9]])
        with self.assertRaisesRegex(ValueError, "leakage"):
            load_incidents(path)

    def test_nonfinite_score_rejected(self):
        path = self.write_rows([["a", "test", 1, "nan", .9]])
        with self.assertRaisesRegex(ValueError, "invalid score"):
            load_incidents(path)

    def test_deterministic_cluster_bootstrap(self):
        path = self.write_rows([["a", "test", 1, .1, .9],
                                ["b", "test", 1, .9, .9],
                                ["c", "test", 0, .1, .1],
                                ["d", "test", 0, .9, .1]])
        incidents = load_incidents(path)
        first = evaluate(incidents, seed=7, replicates=200)
        self.assertEqual(first, evaluate(incidents, seed=7, replicates=200))
        self.assertEqual(first["test_incidents"], 4)
        self.assertFalse(first["statistical_significance_claim"])

    def test_single_class_rejected(self):
        path = self.write_rows([["a", "test", 1, .9, .9]])
        with self.assertRaisesRegex(ValueError, "both incident classes"):
            evaluate(load_incidents(path), replicates=100)


if __name__ == "__main__":
    unittest.main()
