"""Focused contract tests for the non-actuating paired latency runner."""
import json
import tempfile
import unittest
from pathlib import Path

from research_contracts.benchmark_durable_admission import trial


class DurableBenchmarkTests(unittest.TestCase):
    def test_paired_trial_and_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            result = trial(Path(folder), 0)
            self.assertGreaterEqual(result["cold_start_ns"], 0)
            self.assertEqual(len(result["memory_ns"]), 3)
            self.assertEqual(len(result["sqlite_ns"]), 3)
            self.assertTrue(all(type(v) is int and v >= 0
                                for key in ("memory_ns", "sqlite_ns")
                                for v in result[key]))

    def test_repeated_trials_have_isolated_databases(self):
        with tempfile.TemporaryDirectory() as folder:
            first = trial(Path(folder), 0)
            second = trial(Path(folder), 1)
            self.assertEqual(set(first), set(second))
            self.assertTrue((Path(folder) / "trial-0000.sqlite").exists())
            self.assertTrue((Path(folder) / "trial-0001.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
