"""Synthetic abstract-model contract tests; not physical hardware evidence."""
import unittest
from check_command_authorization import State, transition, explore, unsafe_baseline

class SafetyModelTests(unittest.TestCase):
    def test_exhaustive_candidate_has_no_violations(self):
        self.assertEqual(explore()["violating_cases"], 0)
    def test_exhaustive_unsafe_baseline_has_counterexample(self):
        self.assertGreater(explore(unsafe_baseline)["violating_cases"], 0)
    def test_local_emergency_dominates_concurrent_clear(self):
        s, a = transition(State(False, True), command="alert", authenticated=True, fresh=True,
            evidence=True, local_set=True, local_clear=True)
        self.assertTrue(s.emergency)
        self.assertEqual(a, "blocked")
    def test_remote_reset_cannot_clear_latch(self):
        s, a = transition(State(True, True), command="reset_emergency", authenticated=True,
            fresh=True, evidence=True, local_set=False, local_clear=False)
        self.assertTrue(s.emergency)
        self.assertEqual(a, "blocked")
    def test_local_clear_requires_authority(self):
        s, _ = transition(State(True, False), command="alert", authenticated=True,
            fresh=True, evidence=True, local_set=False, local_clear=True)
        self.assertTrue(s.emergency)
    def test_local_clear_with_authority(self):
        s, a = transition(State(True, True), command="alert", authenticated=True,
            fresh=True, evidence=True, local_set=False, local_clear=True)
        self.assertFalse(s.emergency)
        self.assertEqual(a, "network_alert")
    def test_alert_requires_freshness(self):
        _, a = transition(State(False, False), command="alert", authenticated=True,
            fresh=False, evidence=True, local_set=False, local_clear=False)
        self.assertEqual(a, "blocked")
    def test_network_actuation_never_authorized(self):
        for command in ("brake", "steer", "throttle"):
            _, a = transition(State(False, False), command=command, authenticated=True,
                fresh=True, evidence=True, local_set=False, local_clear=False)
            self.assertEqual(a, "blocked")

if __name__ == "__main__":
    unittest.main()
