"""Smoke test for independent authenticated attack labels and evidence output."""
import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "research_contracts" / "bench_authenticated_envelope_attacks.py"
spec = importlib.util.spec_from_file_location("bench_authenticated_envelope_attacks", SCRIPT)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class AuthenticatedAttackBenchTests(unittest.TestCase):
    def test_paired_labels_and_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "attacks.csv"
            summary = bench.run(17, 3, path)
            self.assertEqual(summary["trials"], 9)
            with path.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 9)
            for label in ("honest", "replay", "tamper"):
                self.assertEqual(sum(r["ground_truth"] == label for r in rows), 3)
            self.assertEqual(
                {r["outcome"] for r in rows if r["ground_truth"] == "honest"},
                {"accepted"},
            )

    def test_invalid_dimensions(self):
        with tempfile.TemporaryDirectory() as d:
            for seed, pairs in [(-1, 1), (1, 0), (1, 100001)]:
                with self.assertRaises(ValueError):
                    bench.run(seed, pairs, Path(d) / "invalid.csv")


if __name__ == "__main__":
    unittest.main()
