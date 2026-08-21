import unittest

from runtime_security_monitor import RuntimeSecurityMonitor


class RuntimeSecurityMonitorTests(unittest.TestCase):
    def test_clean_monitor_is_normal(self):
        monitor = RuntimeSecurityMonitor()
        metadata = monitor.metadata()
        self.assertEqual(metadata["last_decision"]["incident_level"], "NORMAL")
        self.assertEqual(metadata["last_decision"]["recommended_action"], "NONE")
        self.assertTrue(metadata["evidence_chain_valid"])

    def test_replay_burst_isolates_network_without_safe_mode(self):
        monitor = RuntimeSecurityMonitor()
        monitor.observe("sync", "REPLAY_DETECTED", subject="vehicle-secret-id")
        decision = monitor.observe("sync", "REPLAY_DETECTED", subject="vehicle-secret-id")
        self.assertEqual(decision.recommended_action, "ISOLATE_NETWORK")
        self.assertFalse(decision.safety_critical)

    def test_ledger_tamper_requests_safe_mode(self):
        monitor = RuntimeSecurityMonitor()
        decision = monitor.observe("ledger", "LEDGER_INTEGRITY_FAILURE", subject="vehicle-01")
        self.assertEqual(decision.incident_level, "CRITICAL")
        self.assertEqual(decision.recommended_action, "SAFE_MODE_REQUEST")
        self.assertTrue(decision.safety_critical)

    def test_service_proof_failure_requests_safe_mode(self):
        monitor = RuntimeSecurityMonitor()
        decision = monitor.observe("control_api", "SERVICE_PROOF_INVALID")
        self.assertEqual(decision.recommended_action, "SAFE_MODE_REQUEST")

    def test_cross_layer_high_events_correlate(self):
        monitor = RuntimeSecurityMonitor()
        monitor.observe("sync", "INVALID_MESSAGE_MAC")
        decision = monitor.observe("consensus", "INVALID_VOTE_SIGNATURE")
        self.assertEqual(decision.recommended_action, "ISOLATE_NETWORK")
        self.assertEqual(set(decision.recent_sources), {"SYNC", "CONSENSUS"})

    def test_bounded_capacity_preserves_verifiable_chain(self):
        monitor = RuntimeSecurityMonitor(capacity=32)
        for index in range(100):
            monitor.observe("sync", f"MALFORMED_INPUT_{index}", subject=f"vehicle-{index}")
        snapshot = monitor.snapshot()
        self.assertEqual(snapshot["retained_events"], 32)
        self.assertTrue(snapshot["evidence_chain_valid"])
        self.assertNotEqual(snapshot["anchor_hash"], "0" * 64)

    def test_raw_subject_and_secret_values_are_not_stored(self):
        monitor = RuntimeSecurityMonitor()
        raw_subject = "VIN-VERY-SENSITIVE-123"
        secret = "never-store-this-secret-value"
        monitor.observe("sync", "AUTH_FAILURE", subject=raw_subject)
        serialized = repr(monitor.snapshot())
        self.assertNotIn(raw_subject, serialized)
        self.assertNotIn(secret, serialized)
        self.assertIn("subject_token", serialized)

    def test_event_reason_is_normalized_and_bounded(self):
        monitor = RuntimeSecurityMonitor()
        monitor.observe("sync", "invalid vote signature with spaces !@#" + "x" * 300)
        event = monitor.snapshot()["events"][0]
        self.assertLessEqual(len(event["reason"]), 128)
        self.assertNotIn(" ", event["reason"])

    def test_reset_clears_evidence_and_incident_state(self):
        monitor = RuntimeSecurityMonitor()
        monitor.observe("ledger", "LEDGER_INTEGRITY_FAILURE")
        monitor.reset()
        snapshot = monitor.snapshot()
        self.assertEqual(snapshot["retained_events"], 0)
        self.assertEqual(snapshot["last_decision"]["recommended_action"], "NONE")
        self.assertTrue(snapshot["evidence_chain_valid"])


if __name__ == "__main__":
    unittest.main()
