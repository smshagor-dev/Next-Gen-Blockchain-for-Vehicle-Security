"""Regression tests; synthetic rows are QA fixtures, not research observations."""
import csv
import tempfile
import unittest
from pathlib import Path
from research_protocols.paired_incident_evaluation import load, evaluate

class IncidentEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "input.csv"
    def tearDown(self):
        self.temp.cleanup()
    def write(self, rows):
        with self.path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["incident_id", "truth", "baseline", "candidate"])
            writer.writerows(rows)
    def test_conflicting_incident_truth_rejected(self):
        self.write([["a",1,1,1],["a",0,0,0]])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            load(self.path)
    def test_nonbinary_rejected(self):
        self.write([["a",1,1,"0.5"]])
        with self.assertRaises(ValueError):
            load(self.path)
    def test_cluster_bootstrap_deterministic(self):
        self.write([["a",1,0,1],["a",1,0,1],["b",0,1,0],
                    ["c",1,1,1],["d",0,0,0]])
        groups = load(self.path)
        a = evaluate(groups, seed=19, repetitions=200)
        self.assertEqual(a, evaluate(groups, seed=19, repetitions=200))
        self.assertEqual(a["incidents"], 4)
        self.assertAlmostEqual(a["paired_cluster_bootstrap"]["fpr"]["difference"], -.5)
        self.assertAlmostEqual(a["paired_cluster_bootstrap"]["tpr"]["difference"], 2/3)
    def test_absent_class_reports_undefined_rate(self):
        self.write([["a",0,0,0],["b",0,1,0]])
        output = evaluate(load(self.path), repetitions=100)
        self.assertIsNone(output["baseline"]["tpr"])
        self.assertIsNone(output["paired_cluster_bootstrap"]["tpr"]["ci95"])

if __name__ == "__main__":
    unittest.main()
