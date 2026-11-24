"""Regression controls for actual child-process termination and restart."""
import tempfile
import unittest
from pathlib import Path
from research_contracts.subprocess_replay_crash import BOUNDARIES, PROTOCOLS, run_case

class SubprocessReplayCrashTests(unittest.TestCase):
    def test_commit_boundary_state_and_rejected_retry(self):
        for protocol in PROTOCOLS:
            for boundary in BOUNDARIES:
                with self.subTest(protocol=protocol, boundary=boundary):
                    with tempfile.TemporaryDirectory() as temp:
                        row = run_case(protocol, boundary, Path(temp))
                    self.assertEqual(row["retry_rejected"], 1)
                    self.assertEqual(row["inconsistent_after_crash"],
                                     int(boundary == "after_first_commit"))
                    self.assertEqual(row["local_committed"],
                                     int(boundary == "after_second_commit" or protocol == "local_first"))
                    self.assertEqual(row["anchor_committed"],
                                     int(boundary == "after_second_commit" or protocol == "reserve_first"))

    def test_repeated_independent_runs(self):
        with tempfile.TemporaryDirectory() as temp:
            first = run_case("reserve_first", "after_first_commit", Path(temp))
        with tempfile.TemporaryDirectory() as temp:
            second = run_case("reserve_first", "after_first_commit", Path(temp))
        self.assertEqual(first, second)

if __name__ == "__main__":
    unittest.main()
