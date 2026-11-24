"""Regression controls for replay-reset and repeated-sender budget exhaustion.

Non-actuating synthetic model: these tests do not establish hardware safety.
"""
import unittest

from research_contracts.epoch_admission_controls import EpochAdmission, Evidence


def ev(sender, nonce, *, epoch=0, incident="incident-a", event="hazard"):
    return Evidence(incident, sender, epoch, nonce, event, True)


class EpochReplayBudgetTests(unittest.TestCase):
    def test_same_epoch_announcement_preserves_replay_state(self):
        gate = EpochAdmission(quorum=2, max_nonces=2)
        self.assertFalse(gate.admit(ev("a", "n1")))
        gate.advance_epoch(0)
        self.assertFalse(gate.admit(ev("a", "n1")))
        self.assertTrue(gate.admit(ev("b", "n2")))

    def test_repeated_sender_does_not_exhaust_nonce_budget(self):
        gate = EpochAdmission(quorum=2, max_nonces=2)
        self.assertFalse(gate.admit(ev("a", "n1")))
        for i in range(50):
            self.assertFalse(gate.admit(ev("a", "other-%d" % i)))
        self.assertTrue(gate.admit(ev("b", "n2")))

    def test_distinct_senders_still_consume_capacity(self):
        gate = EpochAdmission(quorum=3, max_nonces=3)
        self.assertFalse(gate.admit(ev("a", "n1")))
        self.assertFalse(gate.admit(ev("b", "n2")))
        self.assertTrue(gate.admit(ev("c", "n3")))
        self.assertFalse(gate.admit(ev("d", "n4")))

    def test_boolean_epoch_is_rejected(self):
        gate = EpochAdmission()
        with self.assertRaises(ValueError):
            gate.advance_epoch(True)
        self.assertFalse(gate.admit(ev("a", "n1", epoch=True)))

    def test_new_epoch_clears_prior_epoch_state(self):
        gate = EpochAdmission(quorum=2, window=0, max_nonces=2)
        self.assertFalse(gate.admit(ev("a", "n1")))
        gate.advance_epoch(1)
        self.assertFalse(gate.admit(ev("a", "n1", epoch=1)))
        self.assertTrue(gate.admit(ev("b", "n2", epoch=1)))


if __name__ == "__main__":
    unittest.main()
