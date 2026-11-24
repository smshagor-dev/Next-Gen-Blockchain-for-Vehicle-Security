import unittest
from research_contracts.crash_recovery_state_model import State, step, explore

class CrashRecoveryModelTests(unittest.TestCase):
    def test_exhaustive_safety(self):
        self.assertEqual(explore(7)["unsafe_states"], 0)

    def test_no_authorization_with_one_claim(self):
        for first in ("reserve_anchor", "commit_local"):
            state = step(State(), first)
            self.assertFalse(step(state, "authorize").authorized)

    def test_crash_retry_does_not_repair_partial_state(self):
        state = step(State(), "reserve_anchor")
        for action in ("crash", "restart", "retry"):
            state = step(state, action)
        self.assertTrue(state.anchor)
        self.assertFalse(state.local)

    def test_two_claims_required_for_authorization(self):
        state = step(step(State(), "reserve_anchor"), "commit_local")
        self.assertTrue(step(state, "authorize").authorized)

if __name__ == "__main__":
    unittest.main()
