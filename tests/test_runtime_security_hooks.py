import unittest

import runtime_backend_patch as backend_patch
import sync_protocol as sp
from runtime_security_monitor import RuntimeSecurityMonitor, reset_runtime_security_monitor


SHARED_KEY = "s" * 48
VEHICLE_KEY = "v" * 48


class RuntimeSecurityHookTests(unittest.TestCase):
    def setUp(self):
        reset_runtime_security_monitor()

    def test_sync_error_path_records_normalized_event(self):
        monitor = RuntimeSecurityMonitor()
        server = sp.SyncServer(
            shared_key=SHARED_KEY,
            vehicle_key_registry={"CAR1": VEHICLE_KEY},
            runtime_monitor=monitor,
        )
        response = server._error("VALIDATOR_NOT_AUTHORIZED", "k" * 64)
        self.assertIsNotNone(response)
        snapshot = monitor.snapshot()
        self.assertEqual(snapshot["retained_events"], 1)
        self.assertEqual(snapshot["events"][0]["source"], "SYNC")
        self.assertEqual(snapshot["events"][0]["category"], "CONSENSUS_INTEGRITY")
        self.assertTrue(snapshot["evidence_chain_valid"])

    def test_unregistered_vehicle_records_identity_admission_event_without_raw_id(self):
        monitor = RuntimeSecurityMonitor()
        server = sp.SyncServer(
            shared_key=SHARED_KEY,
            vehicle_key_registry={"CAR1": VEHICLE_KEY},
            runtime_monitor=monitor,
        )
        raw_id = "UNREGISTERED-VEHICLE-SECRET-ID"
        with self.assertRaisesRegex(RuntimeError, "UNREGISTERED_VEHICLE"):
            server._vehicle_secret(raw_id)
        serialized = repr(monitor.snapshot())
        self.assertNotIn(raw_id, serialized)
        self.assertIn("IDENTITY_ADMISSION", serialized)

    def test_sync_runtime_metadata_does_not_expose_secrets(self):
        monitor = RuntimeSecurityMonitor()
        server = sp.SyncServer(
            shared_key=SHARED_KEY,
            vehicle_key_registry={"CAR1": VEHICLE_KEY},
            runtime_monitor=monitor,
        )
        server._error("INVALID_VOTE_SIGNATURE", "k" * 64)
        metadata = server.runtime_security_metadata()
        serialized = repr(metadata)
        self.assertNotIn(SHARED_KEY, serialized)
        self.assertNotIn(VEHICLE_KEY, serialized)
        self.assertFalse(metadata["secret_values_stored"])

    def test_backend_error_classifier_never_returns_exception_body(self):
        marker = "TOP-SECRET-SERVER-BODY"
        reason = backend_patch._runtime_reason_from_exception(
            RuntimeError(f"Go backend HTTP 401: {marker}")
        )
        self.assertEqual(reason, "CONTROL_API_HTTP_401")
        self.assertNotIn(marker, reason)

    def test_backend_http_conflict_classifies_replay_or_conflict(self):
        reason = backend_patch._runtime_reason_from_exception(
            RuntimeError("Go backend HTTP 409: replay")
        )
        self.assertEqual(reason, "CONTROL_API_HTTP_409")


if __name__ == "__main__":
    unittest.main()
