"""Negative control for initialization-order confounding in paired trials."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research_contracts import benchmark_durable_admission as bench


class InitializationOrderTests(unittest.TestCase):
    def test_both_randomized_orders_initialize_in_assigned_order(self):
        real_memory = bench.EpochAdmission
        real_sqlite = bench.DurableEpochAdmission
        for order in (("memory", "sqlite"), ("sqlite", "memory")):
            calls = []

            def memory_factory(*args, **kwargs):
                calls.append("memory")
                return real_memory(*args, **kwargs)

            def sqlite_factory(*args, **kwargs):
                calls.append("sqlite")
                return real_sqlite(*args, **kwargs)

            with self.subTest(order=order), tempfile.TemporaryDirectory() as tmp:
                with patch.object(bench, "EpochAdmission", side_effect=memory_factory), \
                     patch.object(bench, "DurableEpochAdmission", side_effect=sqlite_factory):
                    result = bench.trial(Path(tmp), 0, order=order)
                self.assertEqual(calls[:2], list(order))
                self.assertEqual(calls[2:], ["sqlite"])  # restart replay check
                self.assertEqual(result["order"], list(order))
                self.assertGreaterEqual(result["cold_start_ns"], 0)


if __name__ == "__main__":
    unittest.main()
