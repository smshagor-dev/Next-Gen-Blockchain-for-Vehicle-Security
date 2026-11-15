import unittest
from check_emergency_state_machine import State, transition, explore, REMOTE

class EmergencyTraceTests(unittest.TestCase):
    def test_exhaustive_reachable_state_graph(self):
        result = explore(7)
        self.assertEqual(result["transitions_checked"], 360)
        self.assertEqual(result["violations"], 0)
    def test_restart_keeps_emergency(self):
        state, _ = transition(State(), "local_emergency")
        self.assertTrue(transition(state, "restart")[0].emergency)
    def test_remote_reset_cannot_clear_emergency(self):
        state = State(True, True)
        for cmd in REMOTE:
            self.assertEqual(transition(state, "remote_" + cmd, authenticated=True, fresh=True, evidence=True)[0], state)
    def test_local_reset_requires_healthy_sensor(self):
        self.assertTrue(transition(State(True, False), "local_reset")[0].emergency)
        self.assertFalse(transition(State(True, True), "local_reset")[0].emergency)
    def test_sensor_fault_blocks_alert(self):
        self.assertEqual(transition(State(False, False), "remote_alert", authenticated=True, fresh=True, evidence=True)[1], "blocked_sensor_fault")
    def test_alert_all_gates(self):
        for a in (False, True):
            for f in (False, True):
                for e in (False, True):
                    _, action = transition(State(), "remote_alert", authenticated=a, fresh=f, evidence=e)
                    self.assertEqual(action == "network_alert_only", a and f and e)
    def test_remote_actuation_never_allowed(self):
        for cmd in ("brake", "steer", "throttle", "reset_emergency"):
            self.assertEqual(transition(State(), "remote_" + cmd, authenticated=True, fresh=True, evidence=True)[1], "blocked_remote_actuation")
    def test_bad_gate_type_rejected(self):
        with self.assertRaises(ValueError):
            transition(State(), "remote_alert", authenticated=1)
    def test_depth_bounds(self):
        for depth in (-1, 13, True):
            with self.assertRaises(ValueError):
                explore(depth)
    def test_unknown_event(self):
        with self.assertRaises(ValueError):
            transition(State(), "unknown")

if __name__ == "__main__":
    unittest.main()
