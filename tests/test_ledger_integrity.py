import copy
import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

from blockchain import TelemetryData
from ledger_integrity import (
    GoLedgerSnapshotVerifier,
    LedgerIntegrityError,
    go_telemetry_string,
    seal_block_integrity,
    verify_block_integrity,
)
from smartcar_backend import PythonBackend


class LedgerIntegrityTests(unittest.TestCase):
    @staticmethod
    def _go_block(
        index=0,
        previous_hash="0",
        event="GENESIS:GO_BACKEND",
        timestamp="2026-08-21T00:00:00Z",
        vehicle_id="CAR-LEDGER-1",
        receipts=None,
    ):
        telemetry = {
            "speed": 0.0,
            "acceleration": 0.0,
            "fuel_level": 100.0,
            "battery_voltage": 0.0,
            "engine_temp": 0.0,
            "gps_lat": 0.0,
            "gps_lon": 0.0,
            "obstacle_distance": 999.0,
            "emergency_brake_active": False,
            "steering_angle": 0.0,
            "brake_pressure": 0.0,
            "throttle_position": 0.0,
            "rpm": 0.0,
            "odometer": 0.0,
            "driver_heart_rate_bpm": 0.0,
            "driver_drowsiness_score": 0.0,
            "driver_unwell": False,
            "timestamp": timestamp,
        }
        tel_string = go_telemetry_string(telemetry)
        tel_sha2 = hashlib.sha256(tel_string.encode()).hexdigest()
        tel_sha3 = hashlib.sha3_256(tel_string.encode()).hexdigest()
        event_sha2 = hashlib.sha256(event.encode()).hexdigest()
        event_sha3 = hashlib.sha3_256(event.encode()).hexdigest()
        raw = f"{index}{timestamp}{vehicle_id}{tel_sha3}{event_sha3}{previous_hash}"
        block_hash = hashlib.sha3_256(raw.encode()).hexdigest()
        dual = hashlib.sha256(block_hash.encode()).hexdigest() + ":" + hashlib.sha3_256(block_hash.encode()).hexdigest()
        return {
            "index": index,
            "timestamp": timestamp,
            "vehicle_id": vehicle_id,
            "telemetry": telemetry,
            "event_data": event,
            "previous_hash": previous_hash,
            "telemetry_hash_sha2": tel_sha2,
            "telemetry_hash_sha3": tel_sha3,
            "event_hash_sha2": event_sha2,
            "event_hash_sha3": event_sha3,
            "block_hash": block_hash,
            "dual_hash_combined": dual,
            "smart_contract_receipts": list(receipts or []),
        }

    def test_full_metadata_seal_detects_receipt_tampering(self):
        block = self._go_block()
        key = b"k" * 32
        seal_block_integrity(block, key)
        self.assertTrue(verify_block_integrity(block, key))
        block["smart_contract_receipts"].append({"action": "FORGED"})
        self.assertFalse(verify_block_integrity(block, key))

    def test_full_metadata_seal_detects_event_tampering(self):
        block = self._go_block()
        key = b"m" * 32
        seal_block_integrity(block, key)
        block["event_data"] = "FORGED:EVENT"
        self.assertFalse(verify_block_integrity(block, key))

    def test_go_hash_recomputation_rejects_event_tampering(self):
        block = self._go_block()
        verifier = GoLedgerSnapshotVerifier("CAR-LEDGER-1")
        self.assertTrue(verifier.verify_and_track([block], "generation-1"))
        tampered = copy.deepcopy(block)
        tampered["event_data"] = "FORGED:EVENT"
        with self.assertRaises(LedgerIntegrityError):
            GoLedgerSnapshotVerifier("CAR-LEDGER-1").verify_and_track([tampered], "generation-1")

    def test_go_snapshot_rejects_receipt_retroactive_edit(self):
        block = self._go_block(receipts=[{"action": "ORIGINAL"}])
        verifier = GoLedgerSnapshotVerifier("CAR-LEDGER-1")
        verifier.verify_and_track([block], "generation-1")
        tampered = copy.deepcopy(block)
        tampered["smart_contract_receipts"][0]["action"] = "FORGED"
        with self.assertRaises(LedgerIntegrityError):
            verifier.verify_and_track([tampered], "generation-1")

    def test_go_snapshot_rejects_chain_regression(self):
        first = self._go_block()
        second = self._go_block(
            index=1,
            previous_hash=first["block_hash"],
            event="TELEMETRY:UPDATE",
            timestamp="2026-08-21T00:00:01Z",
        )
        verifier = GoLedgerSnapshotVerifier("CAR-LEDGER-1")
        verifier.verify_and_track([first, second], "generation-1")
        with self.assertRaises(LedgerIntegrityError):
            verifier.verify_and_track([first], "generation-1")

    def test_python_backend_verifies_genesis_and_full_metadata_seal(self):
        env = {
            "SMARTCAR_CHECKPOINT_ENABLED": "0",
            "SMARTCAR_EDGE_ENABLED": "0",
            "SMARTCAR_FL_ENABLED": "0",
            "SMARTCAR_PRUNING_ENABLED": "0",
            "SMARTCAR_STORAGE_ENCRYPTION": "0",
            "SMARTCAR_PLATOON_POP_ENABLED": "0",
            "SMARTCAR_VALIDATOR_ID": "authority_node_1",
            "SMARTCAR_VALIDATOR_KEY": "validator-secret-" + ("v" * 40),
        }
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, env, clear=False):
            backend = PythonBackend(
                "CAR-PY-LEDGER",
                "password-strong-enough-for-ledger-test",
                "auth-token-strong-enough-for-ledger-test",
                os.path.join(td, "chain.json"),
            )
            self.assertTrue(backend.verify_chain())
            self.assertTrue(backend.ledger_integrity()["genesis_verified"])
            backend._core.chain[0].smart_contract_receipts.append({"action": "FORGED"})
            self.assertFalse(backend.verify_chain())
            with self.assertRaises(LedgerIntegrityError):
                backend._core._add_block(
                    TelemetryData(timestamp="2026-08-21T00:00:02+00:00"),
                    "TEST:APPEND_AFTER_TAMPER",
                )


if __name__ == "__main__":
    unittest.main()
