import unittest
from research_contracts.evidence_gate_experiment import EvidenceGate, Observation, evaluate

class EvidenceGateTests(unittest.TestCase):
    def obs(self, sender="a", nonce="1", epoch=1, authenticated=True, corroborates=True):
        return Observation("incident",sender,epoch,nonce,"hazard",authenticated,corroborates)

    def test_single_authenticated_sender_cannot_authorize(self):
        gate=EvidenceGate()
        self.assertFalse(gate.admit(self.obs()))
        self.assertFalse(gate.admit(self.obs(nonce="2")))

    def test_distinct_corroboration(self):
        gate=EvidenceGate()
        self.assertFalse(gate.admit(self.obs()))
        self.assertTrue(gate.admit(self.obs(sender="b")))

    def test_replay_and_unauthenticated_rejected(self):
        gate=EvidenceGate()
        self.assertFalse(gate.admit(self.obs()))
        self.assertFalse(gate.admit(self.obs()))
        self.assertFalse(gate.admit(self.obs(sender="b",authenticated=False)))

    def test_emergency_stop_dominates(self):
        gate=EvidenceGate()
        self.assertFalse(gate.admit(self.obs(),local_stop=True))
        self.assertFalse(gate.admit(self.obs(sender="b"),local_stop=True))

    def test_epoch_isolation_and_limit(self):
        gate=EvidenceGate(max_observations=2)
        self.assertFalse(gate.admit(self.obs()))
        self.assertFalse(gate.admit(self.obs(sender="b",epoch=2)))
        self.assertTrue(gate.admit(self.obs(sender="c")))
        self.assertFalse(gate.admit(self.obs(sender="d")))

    def test_seed_reproducibility(self):
        self.assertEqual(evaluate(19,100),evaluate(19,100))
        self.assertEqual(sum(evaluate(19,100)["counts"]["evidence_gate"].values()),100)

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError): EvidenceGate(quorum=1)
        with self.assertRaises(ValueError): evaluate(compromised_fraction=1.1)

if __name__=="__main__": unittest.main()
