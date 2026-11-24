import unittest
from research_contracts.evidence_admission_model import Observation, decide, signature_only, quorum_only

def o(source='a', domain='A', event='hazard', t=10., auth=True, evidence=True):
    return Observation(source,event,t,auth,evidence,domain)

class AdmissionSafetyTests(unittest.TestCase):
    def test_independent_valid_admitted_without_actuation(self):
        d=decide([o(),o('b','B')],11)
        self.assertTrue(d.admitted)
        self.assertFalse(d.remote_actuation_authorized)
    def test_enrolled_false_evidence_rejected_against_baselines(self):
        xs=[o(evidence=False),o('b','B')]
        self.assertFalse(decide(xs,11).admitted)
        self.assertTrue(signature_only(xs,11).admitted)
        self.assertTrue(quorum_only(xs,11).admitted)
    def test_same_domain_sybil_rejected(self):
        self.assertFalse(decide([o(),o('b','A')],11).admitted)
    def test_stale_replay_rejected(self):
        xs=[o(t=1),o('b','B',t=1)]
        self.assertFalse(decide(xs,11).admitted)
        self.assertTrue(quorum_only(xs,11).admitted)
    def test_future_and_nonfinite_clock(self):
        self.assertFalse(decide([o(),o('b','B',t=12)],11).admitted)
        self.assertFalse(decide([o(),o('b','B')],float('nan')).admitted)
    def test_conflict_and_duplicate(self):
        self.assertFalse(decide([o(),o('b','B',event='clear')],11).admitted)
        self.assertFalse(decide([o(),o('a','B')],11).admitted)
    def test_unenrolled_and_malformed_boolean(self):
        self.assertFalse(decide([o(auth=False),o('b','B')],11).admitted)
        self.assertFalse(decide([o(auth=1),o('b','B')],11).admitted)
    def test_policy_invalid(self):
        self.assertFalse(decide([o(),o('b','B')],11,min_domains=True).admitted)
        self.assertFalse(decide([o(),o('b','B')],11,max_age=float('inf')).admitted)

if __name__=='__main__': unittest.main()
