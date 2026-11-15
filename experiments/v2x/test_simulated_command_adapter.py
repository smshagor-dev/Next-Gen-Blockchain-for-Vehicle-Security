"""Synthetic software boundary tests; not physical vehicle evidence."""
import unittest
from itertools import product
from model_command_authority import ACTIONS
from simulated_command_adapter import MemoryAlertSink, SimulationCommandAdapter

class SimulationIsolationTests(unittest.TestCase):
    def test_all_contexts_and_actions(self):
        for bits in product((False, True), repeat=4):
            for action in ACTIONS:
                sink = MemoryAlertSink()
                adapter = SimulationCommandAdapter(sink)
                adapter.set_evidence_context(authenticated=bits[0], fresh=bits[1],
                    admitted=bits[2], network_available=bits[3])
                outcome = adapter.request(action, "hazard")
                self.assertFalse(outcome.vehicle_actuation)
                expected = ["hazard"] if all(bits) and action == "network_alert" else []
                self.assertEqual(sink.alerts, expected)

    def test_emergency_latch_is_local(self):
        sink = MemoryAlertSink()
        adapter = SimulationCommandAdapter(sink)
        adapter.set_evidence_context(authenticated=True, fresh=True,
            admitted=True, network_available=True)
        adapter.local_emergency()
        self.assertFalse(adapter.request("network_alert", "hazard").network_relay)
        adapter.local_reset(locally_authorized=False)
        self.assertTrue(adapter.state.local_emergency)
        adapter.local_reset(locally_authorized=True)
        self.assertTrue(adapter.request("network_alert", "hazard").network_relay)
        self.assertEqual(sink.alerts, ["hazard"])

    def test_invalid_context_and_payload(self):
        adapter = SimulationCommandAdapter(MemoryAlertSink())
        with self.assertRaises(TypeError):
            adapter.set_evidence_context(authenticated=1, fresh=True,
                admitted=True, network_available=True)
        with self.assertRaises(ValueError):
            adapter.request("network_alert", "x" * 4097)
        with self.assertRaises(ValueError):
            adapter.request("actuate", "x")

    def test_reject_external_sink(self):
        with self.assertRaises(TypeError):
            SimulationCommandAdapter(object())

if __name__ == "__main__":
    unittest.main()
