import unittest
from dataclasses import replace
from itertools import product
from research_contracts.evidence_gate import Observation, Decision, decide

class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.valid = Observation(True, True, True, True, frozenset({'peer-a','peer-b'}), 'reporter')

    def test_corroborated_admits_evidence_but_never_actuates(self):
        result = decide(self.valid)
        self.assertEqual(result.decision, Decision.ADMIT_EVIDENCE)
        self.assertFalse(result.physical_command_authorized)

    def test_enrolled_malicious_false_data_quarantined(self):
        self.assertEqual(decide(replace(self.valid, plausible=False)).decision, Decision.QUARANTINE)

    def test_replay_and_spoof_fail_closed(self):
        for field in ('authenticated','fresh','nonce_unique'):
            self.assertEqual(decide(replace(self.valid, **{field: False})).decision, Decision.REJECT)

    def test_self_corroboration_not_counted(self):
        bad = replace(self.valid, corroborating_devices=frozenset({'reporter','peer-a'}))
        self.assertEqual(decide(bad).decision, Decision.QUARANTINE)

    def test_local_emergency_precedence(self):
        self.assertEqual(decide(replace(self.valid, local_emergency_active=True)).reason, 'LOCAL_EMERGENCY_PRECEDENCE')

    def test_invalid_policy_rejected(self):
        self.assertEqual(decide(replace(self.valid, independent_sources_required=0)).decision, Decision.REJECT)

    def test_no_boolean_configuration_actuates(self):
        for auth, fresh, nonce, plausible, emergency in product((False, True), repeat=5):
            obs = replace(self.valid, authenticated=auth, fresh=fresh, nonce_unique=nonce,
                          plausible=plausible, local_emergency_active=emergency)
            self.assertFalse(decide(obs).physical_command_authorized)

if __name__ == '__main__':
    unittest.main()
