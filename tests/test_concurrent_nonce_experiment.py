"""Independent checks of the concurrent nonce component experiment."""
import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "research_contracts"))
from bench_concurrent_nonce import run


class ConcurrentNonceExperimentTests(unittest.TestCase):
    def test_no_duplicate_accepted_under_contention(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out.csv"
            result = run(seed=17, workers=8, attempts=64, capacity=32, output=path)
            with path.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 64)
            self.assertEqual(result["accepted"], 32)
            self.assertEqual(result["duplicate_rejected"], 32)
            self.assertEqual(result["capacity_rejected"], 0)
            accepted_by_nonce = {}
            for row in rows:
                if row["outcome"] == "accepted":
                    key = int(row["attempt_index"]) // 2
                    accepted_by_nonce[key] = accepted_by_nonce.get(key, 0) + 1
            self.assertTrue(all(v == 1 for v in accepted_by_nonce.values()))

    def test_capacity_exhaustion_has_no_extra_admissions(self):
        with tempfile.TemporaryDirectory() as d:
            result = run(seed=19, workers=6, attempts=60, capacity=5,
                         output=Path(d) / "out.csv")
            self.assertEqual(result["accepted"], 5)
            self.assertGreater(result["capacity_rejected"], 0)


if __name__ == "__main__":
    unittest.main()
