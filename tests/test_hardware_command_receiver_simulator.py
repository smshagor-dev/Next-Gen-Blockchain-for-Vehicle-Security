"""Software-only receiver tests: never connect to hardware."""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from hardware_command_receiver_simulator import (
    DurableCommandNonceStore, SimulatedCommandReceiver,
)
from hardware_transport_security import (
    HardwareTransportError, build_authenticated_envelope, build_safe_stop_payload,
)

DEVICE = "bench-node"
SECRET = "receiver-test-secret-" + "x" * 48


class ReceiverSimulationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "nonce.sqlite")
        self.receiver = SimulatedCommandReceiver({DEVICE: SECRET}, self.path)

    def frame(self):
        return build_authenticated_envelope(
            DEVICE, SECRET, "COMMAND", build_safe_stop_payload()
        )

    def test_acceptance_never_means_physical_actuation(self):
        result = self.receiver.receive(self.frame(), expected_device_id=DEVICE)
        self.assertEqual(result["status"], "SIMULATED_ADMISSION_ONLY")
        self.assertFalse(result["actuation_performed"])
        self.assertFalse(result["physical_acknowledgment"])

    def test_replay_after_receiver_restart(self):
        frame = self.frame()
        self.receiver.receive(frame, expected_device_id=DEVICE)
        restarted = SimulatedCommandReceiver({DEVICE: SECRET}, self.path)
        with self.assertRaises(HardwareTransportError) as caught:
            restarted.receive(frame, expected_device_id=DEVICE)
        self.assertEqual(caught.exception.reason, "HW_DURABLE_COMMAND_REPLAY")

    def test_mac_tampering_never_claims_nonce(self):
        frame = self.frame()
        bad = dict(frame)
        bad["mac"] = "0" * 64
        with self.assertRaises(HardwareTransportError):
            self.receiver.receive(bad, expected_device_id=DEVICE)
        self.assertEqual(
            self.receiver.receive(frame, expected_device_id=DEVICE)["status"],
            "SIMULATED_ADMISSION_ONLY",
        )

    def test_wrong_identity_cannot_claim_nonce(self):
        frame = self.frame()
        with self.assertRaises(HardwareTransportError):
            self.receiver.receive(frame, expected_device_id="different-node")
        self.receiver.receive(frame, expected_device_id=DEVICE)

    def test_two_stores_only_one_claim(self):
        first = DurableCommandNonceStore(self.path)
        second = DurableCommandNonceStore(self.path)
        self.assertTrue(first.claim(DEVICE, "nonce1", "now"))
        self.assertFalse(second.claim(DEVICE, "nonce1", "now"))

    def test_memory_store_rejected(self):
        with self.assertRaises(ValueError):
            DurableCommandNonceStore(":memory:")


if __name__ == "__main__":
    unittest.main()
