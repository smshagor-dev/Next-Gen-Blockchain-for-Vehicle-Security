"""Observation boundaries and actual-component integration controls."""
import hashlib
import unittest
from unittest.mock import patch

from experiments.claim_validation.consensus_probe import trial as consensus_trial
from experiments.claim_validation.identity_probe import trial as identity_trial
from experiments.claim_validation.runtime_evidence import (
    canonical, new_scope, _record, is_current,
)


class RuntimeEvidenceTests(unittest.TestCase):
    def test_consensus_observation_does_not_include_policy_truth(self):
        row = consensus_trial(0, 2, False)
        evidence = row["runtime_evidence"]
        self.assertEqual(evidence["facts"]["status"], "ACCEPTED")
        self.assertEqual(evidence["facts"]["quorum_threshold"], 2)
        self.assertNotIn("policy_allows_proposal", evidence["facts"])
        self.assertNotIn("controlled_voters", evidence["facts"])

    def test_identity_observation_independent_of_declared_deny(self):
        row = identity_trial("global_declared_deny", "unlisted_shared", 0)
        facts = row["runtime_evidence"]["facts"]
        self.assertTrue(facts["authenticated_ack"])
        self.assertFalse(facts["registry_member"])
        self.assertNotIn("declared_policy", facts)

    def test_export_integrity_digest(self):
        record = consensus_trial(1, 0, True)["runtime_evidence"]
        digest = record.pop("sha256")
        self.assertEqual(hashlib.sha256(canonical(record)).hexdigest(), digest)
        self.assertEqual(record["trust_boundary"], "local_observer_same_process")

    def test_freshness_scope_kind_and_future_checks(self):
        scope = new_scope()
        with patch("experiments.claim_validation.runtime_evidence.time.monotonic_ns", return_value=100):
            record = _record("identity", scope, {
                "bound": True, "authenticated_ack": True, "registry_member": True,
                "registry_size": 1,
            })
        def check(now, candidate_scope=scope, kind="identity"):
            return is_current(record, kind=kind, scope=candidate_scope,
                              now_ns=now, max_age_ns=10)
        self.assertTrue(check(110))
        self.assertFalse(check(111))
        self.assertFalse(check(99))
        self.assertFalse(check(100, new_scope()))
        self.assertFalse(check(100, kind="consensus"))

    def test_schema_and_exact_types(self):
        facts = {"bound": True, "authenticated_ack": True,
                 "registry_member": True, "registry_size": True}
        with self.assertRaises(ValueError):
            _record("identity", new_scope(), facts)
        facts["registry_size"] = 1
        facts["oracle"] = True
        with self.assertRaises(ValueError):
            _record("identity", new_scope(), facts)


if __name__ == "__main__":
    unittest.main()
