"""Lock contention is observed as SQLITE_BUSY, not inferred from a start signal."""
import tempfile
import unittest
from pathlib import Path
from research_contracts.verified_lock_contention import run, trial

class VerifiedLockContentionTests(unittest.TestCase):
    def test_actual_conflicting_lock_and_recovery(self):
        with tempfile.TemporaryDirectory() as root:
            result = trial(Path(root))
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["lock_result"], "locked")
        self.assertGreaterEqual(result["wait_ns"], 50_000_000)
        self.assertEqual(result["holder_exit"], -9)
        self.assertEqual(result["pre_retry_rows"], [])
        self.assertEqual(result["post_retry_rows"], [("event-1", "digest-1")])

    def test_independent_trials(self):
        result = run(2)
        self.assertTrue(result["all_assertions_passed"], result)
        self.assertEqual(len(result["observations"]), 2)

    def test_bounds(self):
        for count in (0, 101):
            with self.subTest(count=count), self.assertRaises(ValueError):
                run(count)

if __name__ == "__main__":
    unittest.main()
