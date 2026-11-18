import csv
import tempfile
import unittest
from pathlib import Path

from research_contracts.replay_restart_negative_control import run, deliver
from research_contracts.loopback_attack_campaign import Receiver, envelope


class ReplayRestartNegativeControlTests(unittest.TestCase):
    def test_volatile_state_loss_allows_old_packet(self):
        rows = run(seed=19, trials=4)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r["initial"] == "accept" for r in rows))
        self.assertTrue(all(r["same_process_replay"] == "replay" for r in rows))
        self.assertTrue(all(r["after_state_loss"] == "accept" for r in rows))

    def test_existing_receiver_rejects_replay(self):
        receiver = Receiver()
        packet = envelope("replay-test", 1, 0)
        self.assertEqual(deliver(receiver, packet), "accept")
        self.assertEqual(deliver(receiver, packet), "replay")

    def test_invalid_parameters_fail_before_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "should-not-exist.csv"
            for seed, trials in ((-1, 2), (0, 0), (True, 2), (0, 1.5)):
                with self.assertRaises(ValueError):
                    run(seed=seed, trials=trials, output=target)
            self.assertFalse(target.exists())

    def test_csv_trace_is_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "trace.csv"
            run(seed=3, trials=2, output=target)
            with target.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual({r["trial"] for r in rows}, {"0", "1"})


if __name__ == "__main__":
    unittest.main()
