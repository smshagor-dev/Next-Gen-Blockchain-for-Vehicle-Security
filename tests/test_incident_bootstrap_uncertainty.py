import csv
import tempfile
import unittest
from pathlib import Path
from research.paired_incident_analysis import load_pairs, paired_analysis


class IncidentBootstrapTests(unittest.TestCase):
    def make(self, rows):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "data.csv"
        with path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["incident_id", "split", "method", "unsafe_accept", "latency_ms"])
            writer.writeheader()
            writer.writerows(rows)
        return path

    def rows(self):
        return [dict(incident_id=i, split="test", method=m, unsafe_accept=v, latency_ms=10)
                for i, a, b in [("a", 1, 0), ("b", 1, 0), ("c", 0, 0)]
                for m, v in [("base", a), ("new", b)]]

    def test_deterministic_effect(self):
        pairs = load_pairs(self.make(self.rows()), "base", "new")
        a = paired_analysis(pairs, "base", "new", resamples=100)
        self.assertEqual(a, paired_analysis(pairs, "base", "new", resamples=100))
        self.assertAlmostEqual(a["unsafe_accept_rate_difference"], -2 / 3)
        self.assertEqual(a["paired_sign_test_p_two_sided"], 0.5)

    def test_missing_pair(self):
        with self.assertRaisesRegex(ValueError, "unpaired"):
            load_pairs(self.make(self.rows()[:-1]), "base", "new")

    def test_duplicate(self):
        rows = self.rows()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            load_pairs(self.make(rows + [rows[0]]), "base", "new")

    def test_nan_latency(self):
        rows = self.rows()
        rows[0]["latency_ms"] = "nan"
        with self.assertRaisesRegex(ValueError, "invalid latency"):
            load_pairs(self.make(rows), "base", "new")


if __name__ == "__main__":
    unittest.main()
