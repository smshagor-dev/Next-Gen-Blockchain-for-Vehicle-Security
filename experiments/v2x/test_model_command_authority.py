"""Finite-state and transition regressions for offline command authority model."""
import unittest
from dataclasses import replace
from model_command_authority import ACTIONS, State, decide, transition, check_all_states

class SafetyAuthorityModelTests(unittest.TestCase):
    def setUp(self):
        self.ready = State(transport_authenticated=True, fresh_nonce=True,
                           evidence_admitted=True, network_available=True)

    def test_exhaustive_state_space(self):
        result = check_all_states()
        self.assertEqual(result["remote_requests"], 256)
        self.assertEqual(result["actuation_requests_accepted"], 0)
        self.assertEqual(result["network_relays"], 2)

    def test_accepted_alert_only_network(self):
        result = decide(self.ready, "network_alert")
        self.assertTrue(result.network_relay)
        self.assertFalse(result.vehicle_actuation)

    def test_remote_brake_denied_even_when_fully_authenticated(self):
        for action in ACTIONS[1:]:
            with self.subTest(action=action):
                result = decide(self.ready, action)
                self.assertFalse(result.vehicle_actuation)
                self.assertFalse(result.network_relay)

    def test_local_emergency_dominates(self):
        result = decide(replace(self.ready, local_emergency=True), "network_alert")
        self.assertFalse(result.network_relay)

    def test_remote_cannot_clear_emergency(self):
        state = transition(self.ready, "local_emergency")
        for event in ("network_up", "network_down", "invalidate_session",
                      "replay_detected", "local_reset"):
            state = transition(state, event)
            self.assertTrue(state.local_emergency)

    def test_local_reset_requires_local_authorization(self):
        state = transition(self.ready, "local_emergency")
        self.assertTrue(transition(state, "local_reset").local_emergency)
        state = transition(state, "authorize_local_reset")
        state = transition(state, "local_reset")
        self.assertFalse(state.local_emergency)
        self.assertFalse(state.local_reset_authorized)

    def test_session_loss_blocks_alert(self):
        state = transition(self.ready, "invalidate_session")
        self.assertFalse(decide(state, "network_alert").network_relay)

    def test_nonce_replay_blocks_alert(self):
        state = transition(self.ready, "replay_detected")
        self.assertFalse(decide(state, "network_alert").network_relay)

    def test_network_partition_blocks_alert(self):
        state = transition(self.ready, "network_down")
        self.assertFalse(decide(state, "network_alert").network_relay)

    def test_insufficient_evidence_blocks_alert(self):
        state = replace(self.ready, evidence_admitted=False)
        self.assertFalse(decide(state, "network_alert").network_relay)

    def test_strict_boolean_state(self):
        with self.assertRaises(ValueError):
            decide(replace(self.ready, fresh_nonce=1), "network_alert")

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            decide(self.ready, "remote_reset")

    def test_unknown_transition_rejected(self):
        with self.assertRaises(ValueError):
            transition(self.ready, "remote_emergency_clear")

    def test_local_emergency_works_without_network(self):
        state = transition(replace(self.ready, network_available=False), "local_emergency")
        self.assertTrue(state.local_emergency)

    def test_state_unchanged_by_remote_request(self):
        for action in ACTIONS:
            self.assertEqual(decide(self.ready, action).state, self.ready)

if __name__ == "__main__":
    unittest.main()
