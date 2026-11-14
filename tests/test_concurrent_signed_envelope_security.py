"""Executable concurrency and integrity tests for real enrolled-envelope verification.

These are software adversarial regressions, NOT independent paper results.
"""
import concurrent.futures
import json
import threading
import unittest
from datetime import datetime, timezone

from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope, encode_authenticated_envelope,
)

DEVICE = "pi-bench-1"
SECRET = "independent-bench-key-material-0123456789abcdef"

def telemetry():
    from hardware_transport_security import _NUMERIC_RANGES
    payload = {name: (minimum + maximum) / 2 for name, (minimum, maximum) in _NUMERIC_RANGES.items()}
    payload.update(
        emergency_brake_active=False, driver_unwell=False,
        timestamp=datetime.now(timezone.utc).isoformat(), event="BENCH_OBSERVATION",
    )
    return payload

class ConcurrentSignedEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HardwareEnvelopeVerifier({DEVICE: SECRET}, replay_cache_entries=128)

    def test_simultaneous_replay_has_exactly_one_winner(self):
        signed = build_authenticated_envelope(
            DEVICE, SECRET, "TELEMETRY", telemetry(), nonce="ab" * 16,
        )
        raw = encode_authenticated_envelope(signed)
        barrier = threading.Barrier(32)
        def attempt(_):
            barrier.wait(timeout=10)
            try:
                self.verifier.verify(raw, expected_kind="TELEMETRY")
                return "accepted"
            except HardwareTransportError as exc:
                return exc.reason
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            outcomes = list(pool.map(attempt, range(32)))
        self.assertEqual(outcomes.count("accepted"), 1, outcomes)
        self.assertEqual(outcomes.count("HW_REPLAY_DETECTED"), 31, outcomes)

    def test_tampered_mac_valid_envelope_cannot_reach_acceptance(self):
        signed = build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", telemetry())
        tampered = json.loads(json.dumps(signed))
        tampered["payload"]["speed"] = 250.0
        with self.assertRaises(HardwareTransportError):
            self.verifier.verify(encode_authenticated_envelope(tampered), expected_kind="TELEMETRY")
        # Failed tamper attempt must not consume the legitimate nonce.
        valid = self.verifier.verify(encode_authenticated_envelope(signed), expected_kind="TELEMETRY")
        self.assertEqual(valid.device_id, DEVICE)

    def test_cross_session_device_binding(self):
        signed = build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", telemetry())
        with self.assertRaises(HardwareTransportError):
            self.verifier.verify(encode_authenticated_envelope(signed), expected_kind="TELEMETRY", expected_device_id="other-enrolled-device")
        # Identity mismatch must not poison the valid sender's nonce.
        self.verifier.verify(encode_authenticated_envelope(signed), expected_kind="TELEMETRY", expected_device_id=DEVICE)

if __name__ == "__main__":
    unittest.main()
