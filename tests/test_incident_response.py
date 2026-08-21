import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from incident_response import (
    IncidentEvidenceJournal,
    IncidentResponseError,
    IncidentResponseManager,
    build_operator_authorization,
)
from incident_response_runtime import create_runtime_incident_response_manager
from key_provider import EnvironmentKeyProvider
from runtime_security_monitor import RuntimeSecurityMonitor


EVIDENCE_KEY = "incident-evidence-key-" + "E" * 48
OPERATOR_KEY = "incident-operator-key-" + "O" * 48


class IncidentResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = {
            "SMARTCAR_INCIDENT_EVIDENCE_KEY": EVIDENCE_KEY,
            "SMARTCAR_INCIDENT_OPERATOR_KEY": OPERATOR_KEY,
        }
        self.provider = EnvironmentKeyProvider(environ=self.env)
        self.monitor = RuntimeSecurityMonitor(window_sec=5)
        self.journal = IncidentEvidenceJournal(self.temp.name, self.provider)
        self.manager = IncidentResponseManager(
            self.monitor,
            self.journal,
            self.provider,
            required_healthy_observations=3,
        )

    def _open_critical_incident(self):
        self.monitor.observe(
            "ledger",
            "LEDGER_INTEGRITY_FAILURE",
            subject="VIN-SENSITIVE-001",
        )
        metadata = self.manager.evaluate()
        self.assertEqual(metadata["status"]["state"], "OPEN")
        self.assertEqual(metadata["status"]["strongest_action"], "SAFE_MODE_REQUEST")
        return metadata["status"]["incident_id"]

    def _ack(self, incident_id):
        auth = build_operator_authorization(
            self.provider,
            "ACKNOWLEDGE",
            incident_id,
        )
        return self.manager.acknowledge(auth)

    def _age_monitor_and_observe_health(self, count=3):
        future = datetime.now(timezone.utc) + timedelta(seconds=10)
        with patch("runtime_security_monitor._utc_now", return_value=future):
            results = [self.manager.evaluate() for _ in range(count)]
        return results

    def test_incident_is_latched_and_journaled_without_raw_subject(self):
        incident_id = self._open_critical_incident()
        self.assertTrue(incident_id.startswith("inc-"))
        self.assertTrue(self.journal.verify())
        text = Path(self.journal.path).read_text(encoding="utf-8")
        self.assertNotIn("VIN-SENSITIVE-001", text)
        self.assertNotIn(EVIDENCE_KEY, text)
        self.assertNotIn(OPERATOR_KEY, text)
        entry = json.loads(text.splitlines()[0])
        self.assertEqual(entry["record_type"], "INCIDENT_OPENED")
        self.assertEqual(entry["incident_state"], "OPEN")
        self.assertEqual(entry["previous_entry_hash"], "0" * 64)

    def test_journal_reopens_and_verifies_existing_chain(self):
        self._open_critical_incident()
        reopened = IncidentEvidenceJournal(self.temp.name, self.provider)
        self.assertTrue(reopened.verify())
        self.assertEqual(len(reopened.entries()), 1)
        restored = IncidentResponseManager(self.monitor, reopened, self.provider)
        self.assertEqual(restored.status.state, "OPEN")
        self.assertTrue(restored.status.active)

    def test_modified_persisted_journal_fails_closed_on_reopen(self):
        self._open_critical_incident()
        path = Path(self.journal.path)
        entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        entry["incident_state"] = "RECOVERED"
        path.write_text(json.dumps(entry, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(IncidentResponseError, "EVIDENCE_JOURNAL_INVALID"):
            IncidentEvidenceJournal(self.temp.name, self.provider)

    def test_post_open_disk_tamper_blocks_current_process_transition(self):
        incident_id = self._open_critical_incident()
        path = Path(self.journal.path)
        entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        entry["decision_action"] = "NONE"
        path.write_text(json.dumps(entry, sort_keys=True) + "\n", encoding="utf-8")
        self.assertFalse(self.journal.verify())
        auth = build_operator_authorization(self.provider, "ACKNOWLEDGE", incident_id)
        with self.assertRaisesRegex(IncidentResponseError, "EVIDENCE_JOURNAL_INVALID"):
            self.manager.acknowledge(auth)

    def test_forged_operator_acknowledgement_is_rejected(self):
        incident_id = self._open_critical_incident()
        auth = build_operator_authorization(self.provider, "ACKNOWLEDGE", incident_id)
        auth["signature"] = "0" * 64
        with self.assertRaisesRegex(IncidentResponseError, "OPERATOR_SIGNATURE_INVALID"):
            self.manager.acknowledge(auth)
        self.assertEqual(self.manager.status.state, "OPEN")

    def test_operator_authorization_nonce_cannot_be_replayed(self):
        incident_id = self._open_critical_incident()
        auth = build_operator_authorization(self.provider, "ACKNOWLEDGE", incident_id)
        self.manager.acknowledge(auth)
        self.manager.status.state = "OPEN"  # exercise auth replay before state validation
        with self.assertRaisesRegex(IncidentResponseError, "OPERATOR_AUTH_REPLAY"):
            self.manager.acknowledge(auth)

    def test_healthy_window_does_not_replace_operator_acknowledgement(self):
        incident_id = self._open_critical_incident()
        results = self._age_monitor_and_observe_health(4)
        self.assertEqual(results[-1]["status"]["state"], "OPEN")
        self.assertEqual(results[-1]["status"]["healthy_observations"], 0)
        self.assertTrue(incident_id)

    def test_critical_recovery_requires_ack_health_window_and_interlock(self):
        incident_id = self._open_critical_incident()
        self._ack(incident_id)
        results = self._age_monitor_and_observe_health(3)
        self.assertEqual(results[-1]["status"]["state"], "RECOVERY_PENDING")
        self.assertEqual(results[-1]["status"]["healthy_observations"], 3)

        future = datetime.now(timezone.utc) + timedelta(seconds=10)
        with patch("runtime_security_monitor._utc_now", return_value=future):
            no_interlock = build_operator_authorization(self.provider, "RECOVER", incident_id)
            with self.assertRaisesRegex(IncidentResponseError, "SAFETY_INTERLOCK_CONFIRMATION_REQUIRED"):
                self.manager.recover(no_interlock, safety_interlock_confirmed=False)

            recovery = build_operator_authorization(self.provider, "RECOVER", incident_id)
            metadata = self.manager.recover(recovery, safety_interlock_confirmed=True)

        self.assertEqual(metadata["status"]["state"], "RECOVERED")
        self.assertFalse(metadata["status"]["active"])
        self.assertFalse(metadata["automatic_recovery_allowed"])
        self.assertTrue(self.journal.verify())

    def test_network_only_incident_does_not_require_safety_interlock(self):
        self.monitor.observe("sync", "REPLAY_DETECTED")
        self.monitor.observe("sync", "REPLAY_DETECTED")
        incident_id = self.manager.evaluate()["status"]["incident_id"]
        self.assertEqual(self.manager.status.strongest_action, "ISOLATE_NETWORK")
        self.assertFalse(self.manager.status.safety_critical)
        self._ack(incident_id)
        self._age_monitor_and_observe_health(3)

        future = datetime.now(timezone.utc) + timedelta(seconds=10)
        with patch("runtime_security_monitor._utc_now", return_value=future):
            recovery = build_operator_authorization(self.provider, "RECOVER", incident_id)
            metadata = self.manager.recover(recovery)
        self.assertEqual(metadata["status"]["state"], "RECOVERED")

    def test_new_containment_evidence_after_ack_reopens_incident(self):
        incident_id = self._open_critical_incident()
        self._ack(incident_id)
        self.monitor.observe("control_api", "SERVICE_PROOF_INVALID")
        metadata = self.manager.evaluate()
        self.assertEqual(metadata["status"]["incident_id"], incident_id)
        self.assertEqual(metadata["status"]["state"], "OPEN")
        self.assertEqual(metadata["status"]["healthy_observations"], 0)

    def test_monitor_decision_ages_out_without_erasing_evidence(self):
        self.monitor.observe("ledger", "LEDGER_INTEGRITY_FAILURE")
        self.assertEqual(self.monitor.metadata()["last_decision"]["incident_level"], "CRITICAL")
        future = datetime.now(timezone.utc) + timedelta(seconds=10)
        with patch("runtime_security_monitor._utc_now", return_value=future):
            metadata = self.monitor.metadata()
        self.assertEqual(metadata["last_decision"]["incident_level"], "NORMAL")
        self.assertEqual(metadata["retained_events"], 1)
        self.assertTrue(metadata["evidence_chain_valid"])

    def test_incident_keys_are_separate_security_domains(self):
        reused = "R" * 48
        provider = EnvironmentKeyProvider(
            environ={
                "SMARTCAR_INCIDENT_EVIDENCE_KEY": reused,
                "SMARTCAR_INCIDENT_OPERATOR_KEY": reused,
            }
        )
        with self.assertRaises(RuntimeError):
            provider.hmac_sha256("SMARTCAR_INCIDENT_EVIDENCE_KEY", b"payload")

    def test_evidence_filename_path_traversal_is_rejected(self):
        with self.assertRaisesRegex(IncidentResponseError, "INVALID_EVIDENCE_FILENAME"):
            IncidentEvidenceJournal(self.temp.name, self.provider, filename="../outside.jsonl")

    def test_runtime_factory_uses_policy_validated_environment_keys(self):
        env = {
            "SMARTCAR_KEY_PROVIDER": "environment",
            "SMARTCAR_INCIDENT_EVIDENCE_KEY": EVIDENCE_KEY,
            "SMARTCAR_INCIDENT_OPERATOR_KEY": OPERATOR_KEY,
            "SMARTCAR_INCIDENT_EVIDENCE_DIR": self.temp.name,
            "SMARTCAR_INCIDENT_EVIDENCE_FILENAME": "factory-evidence.jsonl",
            "SMARTCAR_INCIDENT_RECOVERY_HEALTHY_OBSERVATIONS": "4",
        }
        monitor = RuntimeSecurityMonitor()
        with patch.dict(os.environ, env, clear=True):
            manager = create_runtime_incident_response_manager(monitor)
        self.assertEqual(manager.required_healthy_observations, 4)
        self.assertEqual(manager.journal.path.name, "factory-evidence.jsonl")
        self.assertTrue(manager.journal.verify())


if __name__ == "__main__":
    unittest.main()
