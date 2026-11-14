"""Non-actuating receiver tests; never evidence of physical command execution."""
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from command_ack_protocol import verify_receipt
from hardware_command_receiver_simulator import SimulatedCommandReceiver
from hardware_transport_security import (
    HardwareTransportError, build_authenticated_envelope, build_safe_stop_payload,
)

DEVICE = "test-bench"
SECRET = "bench-receiver-signing-key-" + "q" * 48
CHALLENGE = "c" * 64


class DurableAdmissionReceiptIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / "durable.sqlite")
        self.receiver = SimulatedCommandReceiver({DEVICE: SECRET}, self.db)

    def frame(self):
        return build_authenticated_envelope(
            DEVICE, SECRET, "COMMAND", build_safe_stop_payload()
        )

    def test_receipt_issued_after_committed_simulation_admission(self):
        command = self.frame()
        result = self.receiver.receive(
            command, expected_device_id=DEVICE, requester_challenge=CHALLENGE
        )
        ack = result["admission_receipt"]
        self.assertTrue(verify_receipt(
            SECRET, ack, device_id=DEVICE, command_nonce=command["nonce"],
            challenge=CHALLENGE,
        ))
        self.assertTrue(ack["admitted"])
        self.assertFalse(ack["physical_acknowledgment"])
        self.assertFalse(ack["actuation_performed"])
        self.assertFalse(result["physical_acknowledgment"])
        self.assertFalse(result["actuation_performed"])

    def test_invalid_challenge_does_not_consume_durable_command(self):
        command = self.frame()
        with self.assertRaises(HardwareTransportError) as caught:
            self.receiver.receive(
                command, expected_device_id=DEVICE, requester_challenge="too-short"
            )
        self.assertEqual(caught.exception.reason, "HW_REQUESTER_CHALLENGE_INVALID")
        ok = self.receiver.receive(
            command, expected_device_id=DEVICE, requester_challenge=CHALLENGE
        )
        self.assertTrue(ok["admission_receipt"]["admitted"])

    def test_loss_of_ack_cannot_duplicate_command_after_restart(self):
        frame = self.frame()
        _lost_result = self.receiver.receive(
            frame, expected_device_id=DEVICE, requester_challenge=CHALLENGE
        )
        with self.assertRaises(HardwareTransportError):
            self.receiver.receive(
                frame, expected_device_id=DEVICE, requester_challenge=CHALLENGE
            )
        restarted = SimulatedCommandReceiver({DEVICE: SECRET}, self.db)
        with self.assertRaises(HardwareTransportError) as caught:
            restarted.receive(
                frame, expected_device_id=DEVICE, requester_challenge=CHALLENGE
            )
        self.assertEqual(caught.exception.reason, "HW_DURABLE_COMMAND_REPLAY")

    def test_old_ack_rejected_by_new_request_challenge(self):
        frame = self.frame()
        result = self.receiver.receive(
            frame, expected_device_id=DEVICE, requester_challenge=CHALLENGE
        )
        ack = result["admission_receipt"]
        self.assertFalse(verify_receipt(
            SECRET, ack, device_id=DEVICE, command_nonce=frame["nonce"],
            challenge="f" * 64,
        ))
        self.assertTrue(verify_receipt(
            SECRET, ack, device_id=DEVICE, command_nonce=frame["nonce"],
            challenge=CHALLENGE,
        ))
        # Exact duplicate receipt remains cryptographically valid if the
        # caller reuses a challenge. Requester must store used challenge IDs.

    def test_wrong_device_or_nonce_receipt_rejected(self):
        frame = self.frame()
        ack = self.receiver.receive(
            frame, expected_device_id=DEVICE, requester_challenge=CHALLENGE
        )["admission_receipt"]
        self.assertFalse(verify_receipt(
            SECRET, ack, device_id="other-bench", command_nonce=frame["nonce"],
            challenge=CHALLENGE,
        ))
        self.assertFalse(verify_receipt(
            SECRET, ack, device_id=DEVICE, command_nonce="a" * 32,
            challenge=CHALLENGE,
        ))

    def test_concurrent_receivers_only_one_durable_claim(self):
        frame = self.frame()
        def attempt(_):
            # Independent verifier/session, one shared on-disk SQLite store.
            receiver = SimulatedCommandReceiver({DEVICE: SECRET}, self.db)
            try:
                receiver.receive(
                    frame, expected_device_id=DEVICE, requester_challenge=CHALLENGE
                )
                return "admitted"
            except HardwareTransportError as err:
                return err.reason
        with ThreadPoolExecutor(max_workers=5) as ex:
            outcomes = list(ex.map(attempt, range(5)))
        self.assertEqual(outcomes.count("admitted"), 1)
        self.assertEqual(outcomes.count("HW_DURABLE_COMMAND_REPLAY"), 4)


if __name__ == "__main__":
    unittest.main()
