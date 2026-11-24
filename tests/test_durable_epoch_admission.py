"""Non-actuating restart and fail-closed controls for durable epoch admission."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from research_contracts.durable_epoch_admission import DurableEpochAdmission
from research_contracts.epoch_admission_controls import Evidence


def ev(sender, nonce, *, epoch=0, incident="incident"):
    return Evidence(incident=incident, sender=sender, epoch=epoch,
                    nonce=nonce, event="hazard", verified=True)


class DurableEpochAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.sqlite"

    def open(self, **kwargs):
        return DurableEpochAdmission(self.path, **kwargs)

    def test_restart_preserves_nonce_and_one_shot(self):
        first = self.open()
        self.assertFalse(first.admit(ev("a", "n1")))
        self.assertFalse(self.open().admit(ev("a", "n1")))
        self.assertTrue(self.open().admit(ev("b", "n2")))
        self.assertFalse(self.open().admit(ev("c", "n3")))

    def test_stop_latch_survives_restart_and_reset_preserves_replay(self):
        first = self.open()
        self.assertFalse(first.admit(ev("a", "n1")))
        first.local_emergency_stop()
        self.assertFalse(self.open().admit(ev("b", "n2")))
        self.assertFalse(self.open().local_reset(operator_confirmed=False))
        self.assertFalse(self.open().admit(ev("b", "n2")))
        self.assertTrue(self.open().local_reset(operator_confirmed=True))
        self.assertFalse(self.open().admit(ev("a", "n1")))
        self.assertTrue(self.open().admit(ev("b", "n2")))

    def test_epoch_window_pins_survive_restart(self):
        a = self.open(window=1)
        a.admit(ev("a", "n1"))
        a.advance_epoch(1)
        self.assertFalse(self.open(window=1).admit(ev("a", "n1")))
        self.assertTrue(self.open(window=1).admit(ev("b", "n2")))
        self.open(window=1).advance_epoch(2)
        self.assertFalse(self.open(window=1).admit(ev("a", "n1")))

    def test_configuration_mismatch_fails_closed(self):
        self.open()
        with self.assertRaises(ValueError):
            self.open(quorum=3)

    def test_corrupted_state_fails_closed(self):
        self.open()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE admission_state SET payload='not json' WHERE id=1")
        with self.assertRaises(ValueError):
            self.open()

    def test_independent_handles_share_one_shot(self):
        left, right = self.open(), self.open()
        self.assertFalse(left.admit(ev("a", "n1")))
        self.assertTrue(right.admit(ev("b", "n2")))
        self.assertFalse(left.admit(ev("c", "n3")))


if __name__ == "__main__":
    unittest.main()
