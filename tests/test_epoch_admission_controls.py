"""Synthetic protocol negative controls; no vehicle actuation or efficacy claims."""
import unittest
from research_contracts.epoch_admission_controls import EpochAdmission, Evidence


def e(sender="a", epoch=4, nonce="n", verified=True):
    return Evidence("incident", sender, epoch, nonce, "hazard", verified)


class EpochAdmissionTests(unittest.TestCase):
    def test_honest_quorum(self):
        g = EpochAdmission()
        g.advance_epoch(4)
        self.assertFalse(g.admit(e()))
        self.assertTrue(g.admit(e("b", 4, "m")))

    def test_stale_future_and_unverified(self):
        g = EpochAdmission()
        g.advance_epoch(4)
        for obs in (e(epoch=2), e(epoch=5), e(verified=False)):
            self.assertFalse(g.admit(obs))
        self.assertFalse(g.admit(e()))
        self.assertTrue(g.admit(e("b", 4, "m")))

    def test_duplicate_and_sender_reuse(self):
        g = EpochAdmission()
        g.advance_epoch(4)
        self.assertFalse(g.admit(e()))
        self.assertFalse(g.admit(e()))
        self.assertFalse(g.admit(e(nonce="new")))
        self.assertTrue(g.admit(e("b", 4, "m")))

    def test_emergency_stop_is_latched(self):
        g = EpochAdmission()
        g.advance_epoch(4)
        g.admit(e())
        g.local_emergency_stop()
        self.assertFalse(g.admit(e("b", 4, "m")))
        self.assertFalse(g.local_reset())
        self.assertFalse(g.admit(e("b", 4, "m")))
        self.assertTrue(g.local_reset(operator_confirmed=True))
        self.assertFalse(g.admit(e("b", 4, "m")))

    def test_epoch_transition_clears_pending(self):
        g = EpochAdmission()
        g.advance_epoch(4)
        g.admit(e())
        g.advance_epoch(5)
        self.assertFalse(g.admit(e("b", 4, "m")))

    def test_bounds_fail_closed(self):
        g = EpochAdmission(max_buckets=1, max_nonces=2)
        g.advance_epoch(4)
        self.assertFalse(g.admit(e()))
        self.assertFalse(g.admit(Evidence("other", "b", 4, "m", "hazard", True)))
        self.assertTrue(g.admit(e("b", 4, "m")))
        self.assertFalse(g.admit(e("c", 4, "o")))

    def test_backward_epoch_rejected(self):
        g = EpochAdmission()
        g.advance_epoch(4)
        with self.assertRaises(ValueError):
            g.advance_epoch(3)


if __name__ == "__main__":
    unittest.main()
