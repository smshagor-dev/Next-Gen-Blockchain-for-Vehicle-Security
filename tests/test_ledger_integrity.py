import copy
import hashlib
import hmac
import unittest

from ledger_integrity import (
    GoLedgerSnapshotVerifier,
    LedgerIntegrityError,
    PythonLedgerIntegrityGuard,
    go_telemetry_string,
    seal_block_integrity,
    verify_block_integrity,
)


class _FakeCrypto:
    mac_key = b"python-ledger-integrity-mac-key-32bytes!!"


class _FakeBlock:
    def __init__(self, index, previous_hash, block_hash, validator_key, vehicle_id="CAR-PY-LEDGER"):
        self.index = index
        self.timestamp = f"2026-08-21T00:00:0{index}+00:00"
        self.vehicle_id = vehicle_id
        self.event_data = "GENESIS" if index == 0 else f"EVENT:{index}"
        self.previous_hash = previous_hash
        self.block_hash = block_hash
        self.block_signature = ""
        self.consensus = "POA"
        self.validator_id = "authority_node_1"
        self.authority_round = index
        message = f"{self.block_hash}|{self.validator_id}|{self.authority_round}"
        self.poa_signature = hmac.new(
            validator_key.encode(), message.encode(), hashlib.sha256
        ).hexdigest()
        self.smart_contract_receipts = []
        self.zkp_proofs = {}
        self.anomaly_reasons = []
        self.edge_summary = {}
        self.forensic_blackbox_payload = {}
        self.fl_model_update_payload = {}
        self.archived_pruned = False
        self.archive_shard_id = ""
        self.archive_root_hash = ""

    def verify(self, crypto, validator_key):
        return bool(crypto and validator_key)

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "vehicle_id": self.vehicle_id,
            "event_data": self.event_data,
            "previous_hash": self.previous_hash,
            "block_hash": self.block_hash,
            "block_signature": self.block_signature,
            "consensus": self.consensus,
            "validator_id": self.validator_id,
            "authority_round": self.authority_round,
            "poa_signature": self.poa_signature,
            "smart_contract_receipts": self.smart_contract_receipts,
            "zkp_proofs": self.zkp_proofs,
            "anomaly_reasons": self.anomaly_reasons,
            "edge_summary": self.edge_summary,
            "forensic_blackbox_payload": self.forensic_blackbox_payload,
            "fl_model_update_payload": self.fl_model_update_payload,
            "archived_pruned": self.archived_pruned,
            "archive_shard_id": self.archive_shard_id,
            "archive_root_hash": self.archive_root_hash,
        }


class _FakeCore:
    def __init__(self):
        self.vehicle_id = "CAR-PY-LEDGER"
        self.consensus = "POA"
        self.crypto = _FakeCrypto()
        self.validator_key = "validator-key-" + ("v" * 32)
        self.authority_registry = {"authority_node_1": self.validator_key}
        self.archive_shards_meta = []
        self.chain = []
        self._create_genesis()

    def _expected_validator(self, index):
        return "authority_node_1"

    def _create_genesis(self):
        genesis = _FakeBlock(
            0,
            "0" * 64,
            hashlib.sha3_256(b"fake-genesis").hexdigest(),
            self.validator_key,
        )
        self.chain.append(genesis)
        return genesis

    def _add_block(self):
        index = len(self.chain)
        block = _FakeBlock(
            index,
            self.chain[-1].block_hash,
            hashlib.sha3_256(f"fake-block-{index}".encode()).hexdigest(),
            self.validator_key,
        )
        self.chain.append(block)
        return block

    def verify_chain(self):
        return True

    def _verify_signed_shard_anchor(self, anchor):
        return {"valid": True}


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
        dual = (
            hashlib.sha256(block_hash.encode()).hexdigest()
            + ":"
            + hashlib.sha3_256(block_hash.encode()).hexdigest()
        )
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

    def test_python_guard_verifies_genesis_and_rejects_retroactive_metadata_edit(self):
        core = _FakeCore()
        guard = PythonLedgerIntegrityGuard(core).install()
        self.assertTrue(core.verify_chain())
        self.assertTrue(guard.metadata()["genesis_verified"])
        core.chain[0].smart_contract_receipts.append({"action": "FORGED"})
        self.assertFalse(core.verify_chain())
        with self.assertRaises(LedgerIntegrityError):
            core._add_block()

    def test_python_guard_seals_new_finalized_block(self):
        core = _FakeCore()
        PythonLedgerIntegrityGuard(core).install()
        block = core._add_block()
        self.assertTrue(verify_block_integrity(block, core.crypto.mac_key))
        self.assertTrue(core.verify_chain())
        block.event_data = "FORGED:EVENT"
        self.assertFalse(core.verify_chain())

    def test_go_hash_recomputation_rejects_event_tampering(self):
        block = self._go_block()
        verifier = GoLedgerSnapshotVerifier("CAR-LEDGER-1")
        self.assertTrue(verifier.verify_and_track([block], "generation-1"))
        tampered = copy.deepcopy(block)
        tampered["event_data"] = "FORGED:EVENT"
        with self.assertRaises(LedgerIntegrityError):
            GoLedgerSnapshotVerifier("CAR-LEDGER-1").verify_and_track(
                [tampered], "generation-1"
            )

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


if __name__ == "__main__":
    unittest.main()
