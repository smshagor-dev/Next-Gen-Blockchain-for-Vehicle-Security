"""Deterministic, non-actuating evidence gate safety properties."""
import unittest
from v2x_evidence_gate import Observation, admit_hazard


def obs(sender, group, *, hazard=True, incident="case-1", time=100., auth=True):
    return Observation(sender, group, incident, time, hazard, auth)


class EvidenceGateProperties(unittest.TestCase):
    def test_independent_honest_witness(self):
        decision = admit_hazard(obs("a", "A"), (obs("b", "B"),), now=101.)
        self.assertTrue(decision.admitted)
        self.assertFalse(decision.command_authorized)
        self.assertEqual(decision.distinct_groups, 2)

    def test_sybil_same_trust_group_cannot_satisfy_quorum(self):
        decision = admit_hazard(obs("a", "A"), (obs("b", "A"), obs("c", "A")), now=101.)
        self.assertFalse(decision.admitted)
        self.assertEqual(decision.reason, "INSUFFICIENT_INDEPENDENT_GROUPS")

    def test_authenticated_false_data_not_self_corrobating(self):
        decision = admit_hazard(obs("malicious", "A"), (), now=101.)
        self.assertFalse(decision.admitted)

    def test_contradiction_denies(self):
        decision = admit_hazard(obs("a", "A"), (obs("b", "B", hazard=False),), now=101.)
        self.assertEqual(decision.reason, "CONTRADICTORY_EVIDENCE")

    def test_unauthenticated_stale_future_and_duplicate_denied(self):
        cases = [
            (obs("b", "B", auth=False), "UNAUTHENTICATED_EVIDENCE"),
            (obs("b", "B", time=90.), "EVIDENCE_OUT_OF_WINDOW"),
            (obs("b", "B", time=103.), "EVIDENCE_OUT_OF_WINDOW"),
            (obs("a", "B"), "DUPLICATE_SENDER"),
        ]
        for witness, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(admit_hazard(obs("a", "A"), (witness,), now=101.).reason, reason)

    def test_witness_budget_denies(self):
        decision = admit_hazard(obs("a", "A"), (obs("b", "B"), obs("c", "C")),
                                now=101., max_witnesses=1)
        self.assertEqual(decision.reason, "WITNESS_BUDGET_EXCEEDED")

    def test_never_authorizes_commands(self):
        for count in range(5):
            witnesses = tuple(obs(str(i), str(i)) for i in range(1, count + 1))
            decision = admit_hazard(obs("0", "0"), witnesses, now=101.)
            self.assertFalse(decision.command_authorized)


if __name__ == "__main__":
    unittest.main()
