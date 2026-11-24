"""Focused contract tests for the non-actuating paired latency runner."""
import json
import random
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

    def test_reverse_order_preserves_one_shot_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            result = trial(Path(folder), 5, order=("sqlite", "memory"))
            self.assertEqual(result["order"], ["sqlite", "memory"])
            self.assertEqual(len(result["sqlite_ns"]), 3)
            self.assertEqual(len(result["memory_ns"]), 3)

    def test_invalid_order_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                trial(Path(folder), 6, order=("sqlite", "sqlite"))

    def test_balanced_seeded_schedule(self):
        seed = 20261120
        orders = [("memory", "sqlite") if i % 2 == 0 else ("sqlite", "memory")
                  for i in range(11)]
        random.Random(seed).shuffle(orders)
        self.assertEqual(sum(x[0] == "memory" for x in orders), 6)
        self.assertEqual(sum(x[0] == "sqlite" for x in orders), 5)
        self.assertEqual(set(orders), {("memory", "sqlite"), ("sqlite", "memory")})

    def test_repeated_trials_have_isolated_databases(self):
        with tempfile.TemporaryDirectory() as folder:
            first = trial(Path(folder), 0)
            second = trial(Path(folder), 1)
            self.assertEqual(set(first), set(second))
            self.assertTrue((Path(folder) / "trial-0000.sqlite").exists())
            self.assertTrue((Path(folder) / "trial-0001.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
