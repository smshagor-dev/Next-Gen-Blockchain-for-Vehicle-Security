"""Process-level pre-commit SIGKILL control; SQLite surrogate only."""
import tempfile
import unittest
from pathlib import Path
from research_contracts.inflight_sqlite_sigkill import run, trial


class InflightSqliteSigkillTests(unittest.TestCase):
    def test_uncommitted_insert_is_rolled_back_and_retry_is_unique(self):
        with tempfile.TemporaryDirectory() as root:
            result = trial(Path(root))
        self.assertEqual(result["kill_returncode"], -9)
        self.assertTrue(result["uncommitted_row_rolled_back"])
        self.assertEqual(result["records_after_retry"], 1)
        self.assertTrue(result["idempotent_retry"])

    def test_multiple_independent_process_trials(self):
        result = run(3)
        self.assertTrue(result["all_assertions_passed"], result)
        self.assertEqual(len(result["observations"]), 3)

    def test_invalid_trial_counts(self):
        for n in (0, 101):
            with self.subTest(n=n), self.assertRaises(ValueError):
                run(n)


if __name__ == "__main__":
    unittest.main()
