"""Authenticated hardware-envelope fault experiments with a real SQLite store.

Runs against production verifier and signed envelope builder, without vehicles
or actuator dispatch. Test counts are deterministic checks, not paper evidence.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hardware_nonce_store import SQLiteNonceStore
from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope, _NUMERIC_RANGES, _BOOL_FIELDS,
)

DEVICE = "bench-node"
SECRET = "lab-independent-secret-0123456789abcdef-9876543210"


def signed_telemetry(nonce):
    now = datetime.now(timezone.utc)
    payload = {key: (low + high) / 2 for key, (low, high) in _NUMERIC_RANGES.items()}
    payload.update({key: False for key in _BOOL_FIELDS})
    payload.update(timestamp=now.isoformat(), event="BENCH_EVENT")
    return build_authenticated_envelope(
        DEVICE, SECRET, "TELEMETRY", payload, timestamp=now, nonce=nonce
    )


class AuthenticatedReplayExperiments(unittest.TestCase):
    def test_restart_replay_and_fresh_admission(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "replay.sqlite")
            store = SQLiteNonceStore(path, provision=True)
            verifier = HardwareEnvelopeVerifier(
                {DEVICE: SECRET}, durable_nonce_store=store
            )
            original = signed_telemetry("a" * 32)
            self.assertEqual(verifier.verify(original).device_id, DEVICE)
            store.close()

            recovered = SQLiteNonceStore(path)
            verifier2 = HardwareEnvelopeVerifier(
                {DEVICE: SECRET}, durable_nonce_store=recovered
            )
            with self.assertRaises(HardwareTransportError) as context:
                verifier2.verify(original)
            self.assertTrue(context.exception.authenticated)
            self.assertEqual(context.exception.reason, "HW_REPLAY_NONCE_REUSED")
            self.assertEqual(
                verifier2.verify(signed_telemetry("b" * 32)).device_id, DEVICE
            )
            recovered.close()

    def test_tampered_mac_cannot_consume_nonce(self):
        with tempfile.TemporaryDirectory() as d:
            store = SQLiteNonceStore(os.path.join(d, "replay.sqlite"), provision=True)
            verifier = HardwareEnvelopeVerifier(
                {DEVICE: SECRET}, durable_nonce_store=store
            )
            original = signed_telemetry("c" * 32)
            tampered = dict(original)
            tampered["payload"] = dict(original["payload"], event="TAMPERED")
            with self.assertRaises(HardwareTransportError) as context:
                verifier.verify(tampered)
            self.assertFalse(context.exception.authenticated)
            self.assertEqual(verifier.verify(original).device_id, DEVICE)
            store.close()

    def test_capacity_failure_does_not_fallback_to_memory(self):
        with tempfile.TemporaryDirectory() as d:
            store = SQLiteNonceStore(
                os.path.join(d, "replay.sqlite"), provision=True, max_claims=1
            )
            verifier = HardwareEnvelopeVerifier(
                {DEVICE: SECRET}, durable_nonce_store=store
            )
            verifier.verify(signed_telemetry("d" * 32))
            with self.assertRaises(HardwareTransportError) as context:
                verifier.verify(signed_telemetry("e" * 32))
            self.assertTrue(context.exception.authenticated)
            self.assertEqual(
                context.exception.reason, "HW_DURABLE_REPLAY_STORE_UNAVAILABLE"
            )
            store.close()


if __name__ == "__main__":
    unittest.main()
