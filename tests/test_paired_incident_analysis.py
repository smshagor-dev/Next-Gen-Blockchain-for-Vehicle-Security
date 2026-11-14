"""Contract tests for incident-level paired analysis (synthetic inputs only)."""
import csv
import tempfile
import unittest
from pathlib import Path

from experiments.v2x.paired_incident_analysis import analyze


class PairedIncidentAnalysisTests(unittest.TestCase):
    def run_rows(self, rows):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "incidents.csv"
            with path.open("w", newline="") as output:
                writer = csv.writer(output)
                writer.writerow(("incident_id", "truth", "baseline", "candidate"))
                writer.writerows(rows)
            return analyze(path)

    def test_no_discordance_is_not_significant(self):
        result = self.run_rows([("a", 1, 1, 1), ("b", 0, 0, 0)])
        self.assertEqual(result["mcnemar_exact_two_sided_p"], 1)

    def test_exact_binomial_for_six_improvements(self):
        result = self.run_rows([(str(i), 1, 0, 1) for i in range(6)])
        self.assertEqual(result["candidate_only_correct"], 6)
        self.assertAlmostEqual(result["mcnemar_exact_two_sided_p"], 0.03125)

    def test_duplicate_incident_rejected(self):
        with self.assertRaises(ValueError):
            self.run_rows([("a", 1, 1, 1), ("a", 0, 0, 0)])

    def test_nonbinary_rejected(self):
        with self.assertRaises(ValueError):
            self.run_rows([("a", 1, 2, 1)])


if __name__ == "__main__":
    unittest.main()
