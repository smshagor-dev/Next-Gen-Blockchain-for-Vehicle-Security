"""Non-actuating independent-process crash recovery controls."""
import unittest
from research_contracts.lock_release_latency import run

class LockReleaseLatencyTests(unittest.TestCase):
    def test_sigkill_survivor(self):
        report = run(trials=2,hold_ms=100)
        self.assertTrue(report["passed"],report)
        for trial in report["observations"]:
            self.assertGreater(trial["wait_ns"],0)
            self.assertEqual(trial["rows_seen"],[])
            self.assertEqual(trial["final_rows"],[("same-event","survivor")])

    def test_invalid_trials(self):
        for n in (0,101):
            with self.assertRaises(ValueError):
                run(trials=n)

    def test_invalid_hold_ms(self):
        for n in (0,2001):
            with self.assertRaises(ValueError):
                run(trials=1,hold_ms=n)

if __name__ == "__main__":
    unittest.main()
