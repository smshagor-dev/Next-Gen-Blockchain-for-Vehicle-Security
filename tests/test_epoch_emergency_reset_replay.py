"""Non-actuating emergency reset and one-shot authorization regression controls."""
import unittest
from research_contracts.epoch_admission_controls import EpochAdmission, Evidence


def e(sender, nonce, *, epoch=0, incident="hazard"):
    return Evidence(incident, sender, epoch, nonce, "brake_alert", True)


class EmergencyReplayTests(unittest.TestCase):
    def test_reset_cannot_resurrect_pre_stop_nonce(self):
        gate = EpochAdmission()
        self.assertFalse(gate.admit(e("a", "n1")))
        gate.local_emergency_stop()
        self.assertFalse(gate.admit(e("b", "n2")))
        self.assertFalse(gate.local_reset())
        self.assertTrue(gate.local_reset(operator_confirmed=True))
        self.assertFalse(gate.admit(e("a", "n1")))
        self.assertTrue(gate.admit(e("b", "n2")))

    def test_reset_cannot_reissue_admitted_incident(self):
        gate = EpochAdmission()
        self.assertFalse(gate.admit(e("a", "n1")))
        self.assertTrue(gate.admit(e("b", "n2")))
        gate.local_emergency_stop()
        self.assertTrue(gate.local_reset(operator_confirmed=True))
        self.assertFalse(gate.admit(e("c", "n3")))
        self.assertFalse(gate.admit(e("a", "n1")))

    def test_quorum_emits_at_most_one_authorization(self):
        gate = EpochAdmission(quorum=2)
        self.assertFalse(gate.admit(e("a", "n1")))
        self.assertTrue(gate.admit(e("b", "n2")))
        self.assertFalse(gate.admit(e("c", "n3")))

    def test_expired_epoch_reclaims_one_shot_history(self):
        gate = EpochAdmission(window=1, max_buckets=1, max_nonces=2)
        self.assertFalse(gate.admit(e("a", "n1")))
        self.assertTrue(gate.admit(e("b", "n2")))
        gate.advance_epoch(2)
        self.assertFalse(gate.admit(e("a", "n1", epoch=0)))
        self.assertFalse(gate.admit(e("a", "n1", epoch=2)))
        self.assertTrue(gate.admit(e("b", "n2", epoch=2)))

    def test_emergency_does_not_reclaim_capacity_within_epoch(self):
        gate = EpochAdmission(max_buckets=1, max_nonces=2)
        self.assertFalse(gate.admit(e("a", "n1")))
        gate.local_emergency_stop()
        self.assertTrue(gate.local_reset(operator_confirmed=True))
        self.assertFalse(gate.admit(e("c", "n3", incident="other")))
        self.assertTrue(gate.admit(e("b", "n2")))


if __name__ == "__main__":
    unittest.main()
