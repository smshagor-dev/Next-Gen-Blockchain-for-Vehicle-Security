"""Contract tests: synthetic inputs only, never manuscript evidence."""
import csv
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "experiments/v2x/paired_incident_uncertainty.py"
spec = importlib.util.spec_from_file_location("paired_incident_uncertainty", MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class PairedIncidentTests(unittest.TestCase):
    def test_identical_predictions_have_zero_effect(self):
        rows = [(("s", str(i)), i % 2, i % 2, i % 2) for i in range(20)]
        result = mod.compare(rows, replicates=100, seed=1)
        self.assertEqual(result["effect"], 0)
        self.assertEqual(result["ci95"], [0, 0])

    def test_improvement_is_paired_and_reproducible(self):
        rows = [(("s", str(i)), i % 2, 1 - i % 2, i % 2) for i in range(20)]
        a = mod.compare(rows, replicates=100, seed=3)
        self.assertEqual(a, mod.compare(rows, replicates=100, seed=3))
        self.assertEqual(a["effect"], 1)
        self.assertEqual(a["ci95"], [1, 1])

    def test_one_class_is_not_significance(self):
        rows = [(("s", str(i)), 1, 0, 1) for i in range(40)]
        self.assertIsNone(mod.compare(rows, replicates=50)["effect"])

    def test_reject_duplicate_incidents_and_extra_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incidents.csv"
            with path.open("w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(mod.COLUMNS)
                writer.writerow(["s", "i", "1", "0", "1"])
                writer.writerow(["s", "i", "1", "0", "1"])
            with self.assertRaises(ValueError):
                mod.read_incidents(path)
            path.write_text("scenario_id,incident_id,truth,baseline,proposed,attacker_label\ns,i,1,0,1,1\n")
            with self.assertRaises(ValueError):
                mod.read_incidents(path)


if __name__ == "__main__":
    unittest.main()
