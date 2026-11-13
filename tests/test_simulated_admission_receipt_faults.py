"""Fault-injection regressions for simulated command admission receipts.

No CAN, GPIO, serial, or physical ECU is accessed.
"""
import tempfile
import unittest
from pathlib import Path

from command_ack_protocol import verify_receipt
from hardware_command_receiver_simulator import SimulatedCommandReceiver
from hardware_transport_security import (
    HardwareTransportError, build_authenticated_envelope, build_safe_stop_payload,
)

DEVICE = "bench-node"
KEY = "receiver-test-secret-" + "x" * 48
CHALLENGE = "a" * 32


class AdmissionReceiptFaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "replay.sqlite")
        self.receiver = SimulatedCommandReceiver({DEVICE: KEY}, self.path)

    def frame(self):
        return build_authenticated_envelope(
            DEVICE, KEY, "COMMAND", build_safe_stop_payload()
        )

    def test_receipt_binds_actual_durable_claim(self):
        frame = self.frame()
        result = self.receiver.receive_with_receipt(
            frame, expected_device_id=DEVICE, challenge=CHALLENGE
        )
        nonce = result["admission"]["nonce"]
        self.assertTrue(verify_receipt(
            KEY, result["receipt"], device_id=DEVICE,
            command_nonce=nonce, challenge=CHALLENGE
        ))
        self.assertFalse(result["receipt"]["actuation_performed"])
        self.assertFalse(result["receipt"]["physical_acknowledgment"])

    def test_lost_receipt_retry_does_not_re_admit(self):
        frame = self.frame()
        self.receiver.receive_with_receipt(
            frame, expected_device_id=DEVICE, challenge=CHALLENGE
        )  # Simulate lost reply after durable commit.
        restarted = SimulatedCommandReceiver({DEVICE: KEY}, self.path)
        with self.assertRaises(HardwareTransportError) as caught:
            restarted.receive_with_receipt(
                frame, expected_device_id=DEVICE, challenge="b" * 32
            )
        self.assertEqual(caught.exception.reason, "HW_DURABLE_COMMAND_REPLAY")

    def test_delayed_receipt_cannot_satisfy_new_challenge(self):
        frame = self.frame()
        receipt = self.receiver.receive_with_receipt(
            frame, expected_device_id=DEVICE, challenge=CHALLENGE
        )["receipt"]
        self.assertFalse(verify_receipt(
            KEY, receipt, device_id=DEVICE,
            command_nonce=receipt["command_nonce"], challenge="b" * 32
        ))

    def test_bad_challenge_does_not_consume_nonce(self):
        frame = self.frame()
        with self.assertRaises(ValueError):
            self.receiver.receive_with_receipt(
                frame, expected_device_id=DEVICE, challenge="invalid"
            )
        accepted = self.receiver.receive_with_receipt(
            frame, expected_device_id=DEVICE, challenge=CHALLENGE
        )
        self.assertTrue(accepted["receipt"]["admitted"])

    def test_duplicate_receipt_is_not_second_admission(self):
        frame = self.frame()
        first = self.receiver.receive_with_receipt(
            frame, expected_device_id=DEVICE, challenge=CHALLENGE
        )
        copied = dict(first["receipt"])
        self.assertEqual(copied, first["receipt"])
        with self.assertRaises(HardwareTransportError):
            self.receiver.receive_with_receipt(
                frame, expected_device_id=DEVICE, challenge=CHALLENGE
            )


if __name__ == "__main__":
    unittest.main()
