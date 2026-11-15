"""Synthetic contract tests; not publishable V2X evidence."""
import tempfile
import unittest
from pathlib import Path
from experiments.v2x.audit_trial_coverage import audit, CoverageError

class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def check(self, world="incident_id,cluster_id,truth\na,A,1\nb,B,0\n",
              candidate="incident_id,alert\na,1\n",
              baseline="incident_id,alert\n"):
        return audit(self.write("world.csv", world),
                     self.write("candidate.csv", candidate),
                     self.write("baseline.csv", baseline))

    def test_missing_positive_is_false_negative(self):
        result = self.check()
        self.assertEqual(result["methods"]["baseline"]["confusion"],
                         {"tp": 0, "fp": 0, "tn": 1, "fn": 1})
        self.assertEqual(result["methods"]["candidate"]["confusion"]["tp"], 1)

    def test_unknown_incident_rejected(self):
        with self.assertRaises(CoverageError):
            self.check(candidate="incident_id,alert\nx,1\n")

    def test_duplicate_rejected(self):
        with self.assertRaises(CoverageError):
            self.check(candidate="incident_id,alert\na,1\na,0\n")

    def test_invalid_truth_rejected(self):
        with self.assertRaises(CoverageError):
            self.check(world="incident_id,cluster_id,truth\na,A,attack\n")

    def test_ragged_rejected(self):
        with self.assertRaises(CoverageError):
            self.check(world="incident_id,cluster_id,truth\na,A\n")

    def test_leaking_columns_rejected(self):
        with self.assertRaises(CoverageError):
            self.check(candidate="incident_id,alert,truth\na,1,1\n")

    def test_repeatable(self):
        self.assertEqual(self.check(), self.check())

if __name__ == "__main__":
    unittest.main()
