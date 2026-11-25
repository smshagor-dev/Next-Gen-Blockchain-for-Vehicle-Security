"""Research gate controls; constructed observations are not empirical results."""
import unittest
from dataclasses import replace

from experiments.claim_validation.claim_gate import evaluate_claim
from experiments.claim_validation.runtime_evidence import Observation, new_scope, _record
from experiments.claim_validation.consensus_probe import trial as consensus_trial
from experiments.claim_validation.identity_probe import trial as identity_trial


class ClaimGateTests(unittest.TestCase):
    def setUp(self):
        self.scope = new_scope()
        self.facts = {"completed": True, "matched_session": True,
                      "client_mode": "PQC_KEM", "server_mode": "PQC_KEM",
                      "negotiated_kem": "ML-KEM-512"}
        self.obs = _record("handshake", self.scope, self.facts)

    def decide(self, obs, posture="STRONG", scope=None, now=None):
        return evaluate_claim("mlkem512_session", posture, obs,
                              expected_scope=self.scope if scope is None else scope,
                              now_ns=self.obs.monotonic_ns if now is None else now,
                              max_age_ns=10)

    def test_scoped_mlkem_positive(self):
        self.assertEqual(self.decide(self.obs).eligibility, "ELIGIBLE")

    def test_fallback_not_supported(self):
        for mode in ("ECDH", "PSK"):
            facts = dict(self.facts, client_mode=mode, server_mode=mode, negotiated_kem="")
            obs = _record("handshake", self.scope, facts)
            self.assertEqual(self.decide(obs, now=obs.monotonic_ns).eligibility, "NOT_SUPPORTED")

    def test_missing_stale_future_wrong_scope_and_non_strong(self):
        for result in (self.decide(None), self.decide(self.obs, now=self.obs.monotonic_ns+11),
                       self.decide(self.obs, now=self.obs.monotonic_ns-1),
                       self.decide(self.obs, scope=new_scope()),
                       self.decide(self.obs, posture="GUARDED")):
            self.assertEqual(result.eligibility, "WITHHELD")

    def test_schema_and_inconsistent_observation(self):
        malformed = replace(self.obs, facts=(("completed", True),))
        self.assertEqual(self.decide(malformed).reason, "EVIDENCE_SCHEMA_INVALID")
        facts = dict(self.facts, completed=False)
        obs = _record("handshake", self.scope, facts)
        self.assertEqual(self.decide(obs, now=obs.monotonic_ns).reason, "EVIDENCE_INCONSISTENT")

    def test_consensus_honesty_and_policy_truth_not_inferred(self):
        row = consensus_trial(0, 2, False)
        self.assertEqual(row["claim_gate"]["recorded_quorum_acceptance"]["eligibility"], "ELIGIBLE")
        for claim in ("honest_validator_quorum", "external_policy_validity"):
            self.assertEqual(row["claim_gate"][claim]["eligibility"], "WITHHELD")
        positive = consensus_trial(0, 0, True)
        self.assertEqual(positive["claim_gate"]["external_policy_validity"]["eligibility"], "WITHHELD")

    def test_actual_enrolled_and_unlisted_admissions(self):
        accepted = identity_trial("registry_strict", "enrolled_valid", 0)
        self.assertEqual(accepted["claim_gate"]["eligibility"], "ELIGIBLE")
        unlisted = identity_trial("global_declared_deny", "unlisted_shared", 0)
        self.assertEqual(unlisted["claim_gate"]["eligibility"], "NOT_SUPPORTED")


if __name__ == "__main__":
    unittest.main()
