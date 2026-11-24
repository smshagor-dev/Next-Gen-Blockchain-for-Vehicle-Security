"""Non-actuating controls for overlapping epoch replay history."""
import unittest
from research_contracts.epoch_admission_controls import EpochAdmission, Evidence


def observation(sender, nonce, epoch):
    return Evidence("incident", sender, epoch, nonce, "hazard", True)


class EpochWindowReplayTests(unittest.TestCase):
    def test_previous_epoch_replay_rejected_after_advance(self):
        gate = EpochAdmission(window=1, max_nonces=3)
        self.assertFalse(gate.admit(observation("a", "n", 0)))
        gate.advance_epoch(1)
        self.assertFalse(gate.admit(observation("a", "n", 0)))
        self.assertTrue(gate.admit(observation("b", "m", 0)))

    def test_previous_epoch_quorum_state_is_preserved(self):
        gate = EpochAdmission(window=1)
        self.assertFalse(gate.admit(observation("a", "n", 0)))
        gate.advance_epoch(1)
        self.assertTrue(gate.admit(observation("b", "m", 0)))

    def test_expired_epoch_releases_capacity(self):
        gate = EpochAdmission(window=1, max_buckets=1, max_nonces=2)
        self.assertFalse(gate.admit(observation("a", "n", 0)))
        gate.advance_epoch(2)
        self.assertFalse(gate.admit(observation("a", "n", 0)))
        self.assertFalse(gate.admit(observation("c", "fresh", 2)))
        self.assertTrue(gate.admit(observation("d", "fresh2", 2)))

    def test_same_epoch_does_not_release_capacity(self):
        gate = EpochAdmission(window=1, max_buckets=1, max_nonces=2)
        self.assertFalse(gate.admit(observation("a", "n", 0)))
        gate.advance_epoch(0)
        self.assertFalse(gate.admit(observation("a", "n", 0)))
        self.assertTrue(gate.admit(observation("b", "m", 0)))


if __name__ == "__main__":
    unittest.main()
