import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import sync_protocol as sp


KEY = "k" * 48
OTHER_KEY = "m" * 48
VAL_KEYS = {
    "VAL1": "validator-one-key-" + "a" * 40,
    "VAL2": "validator-two-key-" + "b" * 40,
    "VAL3": "validator-three-key-" + "c" * 40,
}


def build_block(index=0, previous_hash=None, event_data="GENESIS"):
    if previous_hash is None:
        previous_hash = sp.GENESIS_PREVIOUS_HASH
    timestamp = datetime.now(timezone.utc).isoformat()
    telemetry_hash = sp.sha3_256("telemetry")
    event_hash = sp.sha3_256(event_data)
    block_hash = sp.sha3_256(f"{index}{timestamp}CAR1{telemetry_hash}{event_hash}{previous_hash}")
    return {
        "index": index,
        "timestamp": timestamp,
        "vehicle_id": "CAR1",
        "telemetry_hash_sha3": telemetry_hash,
        "event_hash_sha3": event_hash,
        "event_data": event_data,
        "previous_hash": previous_hash,
        "block_hash": block_hash,
        "consensus": "NONE",
    }


class SyncSecurityTests(unittest.TestCase):
    def test_missing_mac_rejected_when_session_exists(self):
        raw = sp.create_message(sp.MessageType.PING, {}).decode()
        self.assertIsNone(sp.verify_message(raw, KEY))

    def test_valid_mac_accepts_then_nonce_replay_rejected(self):
        raw = sp.create_message(sp.MessageType.PING, {}, KEY).decode()
        cache = {}
        self.assertIsNotNone(sp.verify_message(raw, KEY, replay_cache=cache))
        self.assertIsNone(sp.verify_message(raw, KEY, replay_cache=cache))

    def test_stale_authenticated_message_rejected(self):
        msg = {
            "type": sp.MessageType.PING,
            "payload": {},
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
            "nonce": "a" * 32,
        }
        msg["mac"] = sp.hmac.new(KEY.encode(), sp._canonical_json(msg).encode(), sp.hashlib.sha256).hexdigest()
        self.assertIsNone(sp.verify_message(sp._canonical_json(msg), KEY, replay_cache={}, max_skew_sec=15))

    def test_authenticated_handshake_requires_enrolled_identity(self):
        server = sp.SyncServer(shared_key=KEY, vehicle_key_registry={"CAR1": KEY})
        msg = {
            "type": sp.MessageType.HANDSHAKE,
            "payload": {"vehicle_id": "CAR1", "client_version": "2.0"},
            "timestamp": sp._utc_now(),
            "nonce": sp._nonce(),
        }
        msg["handshake_mac"] = sp._handshake_mac(KEY, msg)
        response = server._process_message(msg, "client-1", "")
        self.assertIsNotNone(response)
        self.assertEqual(server._bound_vehicle("client-1"), "CAR1")
        self.assertIsNone(server._process_message(msg, "client-2", ""))

    def test_global_psk_only_admission_is_denied_by_default(self):
        with patch.dict(os.environ, {"SMARTCAR_SYNC_ALLOW_GLOBAL_PSK_ADMISSION": "0"}, clear=False):
            server = sp.SyncServer(shared_key=KEY)
            msg = {
                "type": sp.MessageType.HANDSHAKE,
                "payload": {"vehicle_id": "CAR1", "client_version": "2.0"},
                "timestamp": sp._utc_now(),
                "nonce": sp._nonce(),
            }
            msg["handshake_mac"] = sp._handshake_mac(KEY, msg)
            self.assertIsNone(server._process_message(msg, "client-global", ""))
            self.assertEqual(server._bound_vehicle("client-global"), "")

    def test_vehicle_registry_rejects_unknown_vehicle(self):
        server = sp.SyncServer(shared_key=KEY, vehicle_key_registry={"CAR1": KEY})
        msg = {
            "type": sp.MessageType.HANDSHAKE,
            "payload": {"vehicle_id": "CAR2", "client_version": "2.0"},
            "timestamp": sp._utc_now(),
            "nonce": sp._nonce(),
        }
        msg["handshake_mac"] = sp._handshake_mac(OTHER_KEY, msg)
        self.assertIsNone(server._process_message(msg, "client-x", ""))

    def test_invalid_chain_does_not_overwrite_server_state(self):
        server = sp.SyncServer(shared_key=KEY)
        good = build_block()
        server.server_chain = [good]
        session = "s" * 64
        server.clients["client-1"] = {"vehicle_id": "CAR1", "session_key": session, "replay_cache": {}}
        bad = dict(good)
        bad["event_data"] = "TAMPERED"
        response = server._process_message({
            "type": sp.MessageType.SYNC_REQUEST,
            "payload": {"vehicle_id": "CAR1", "chain": [bad]},
            "timestamp": sp._utc_now(), "nonce": sp._nonce(),
        }, "client-1", session)
        self.assertEqual(server.server_chain, [good])
        decoded = sp.verify_message(response.decode(), session)
        self.assertFalse(decoded["payload"]["accepted"])

    def test_single_block_chain_must_have_valid_genesis_hash(self):
        server = sp.SyncServer(shared_key=KEY)
        self.assertTrue(server._verify_chain([build_block()]))
        self.assertFalse(server._verify_chain([build_block(previous_hash="bad")]))

    def test_session_vehicle_spoof_is_rejected(self):
        server = sp.SyncServer(shared_key=KEY)
        session = "s" * 64
        server.clients["client-1"] = {"vehicle_id": "CAR1", "session_key": session, "replay_cache": {}}
        response = server._process_message({
            "type": sp.MessageType.SYNC_REQUEST,
            "payload": {"vehicle_id": "CAR2", "chain": [build_block()]},
            "timestamp": sp._utc_now(), "nonce": sp._nonce(),
        }, "client-1", session)
        decoded = sp.verify_message(response.decode(), session)
        self.assertEqual(decoded["payload"]["reason"], "VEHICLE_IDENTITY_MISMATCH")

    def test_forged_voter_id_rejected_before_vote_validation(self):
        server = sp.SyncServer(shared_key=KEY, validator_ids=["CAR1"])
        session = "s" * 64
        server.clients["client-1"] = {"vehicle_id": "CAR1", "session_key": session, "replay_cache": {}}
        response = server._process_message({
            "type": sp.MessageType.VOTE_SUBMIT,
            "payload": {"vehicle_id": "CAR1", "proposal_id": "P1", "voter_id": "CAR2", "vote": True},
            "timestamp": sp._utc_now(), "nonce": sp._nonce(),
        }, "client-1", session)
        decoded = sp.verify_message(response.decode(), session)
        self.assertEqual(decoded["payload"]["reason"], "VOTER_IDENTITY_MISMATCH")
        self.assertEqual(server.vote_registry, {})

    def test_non_validator_vote_rejected(self):
        server = sp.SyncServer(shared_key=KEY, validator_ids=["CAR9"])
        session = "s" * 64
        server.clients["client-1"] = {"vehicle_id": "CAR1", "session_key": session, "replay_cache": {}}
        response = server._process_message({
            "type": sp.MessageType.VOTE_SUBMIT,
            "payload": {"vehicle_id": "CAR1", "proposal_id": "P1", "voter_id": "CAR1", "vote": True},
            "timestamp": sp._utc_now(), "nonce": sp._nonce(),
        }, "client-1", session)
        decoded = sp.verify_message(response.decode(), session)
        self.assertEqual(decoded["payload"]["reason"], "VALIDATOR_NOT_AUTHORIZED")

    def test_signed_votes_require_full_validator_set_quorum(self):
        server = sp.SyncServer(shared_key=KEY, authority_registry=VAL_KEYS, validator_ids=list(VAL_KEYS))
        proposal_hash = "4" * 64
        proposal_ts = sp._utc_now()
        session = "s" * 64

        def cast(client_id, validator):
            server.clients[client_id] = {"vehicle_id": validator, "session_key": session, "replay_cache": {}}
            signature = sp.sign_vote("P-Q", proposal_hash, validator, True, 1, proposal_ts, VAL_KEYS[validator])
            response = server._process_message({
                "type": sp.MessageType.VOTE_SUBMIT,
                "payload": {
                    "vehicle_id": validator,
                    "voter_id": validator,
                    "proposal_id": "P-Q",
                    "proposal_hash": proposal_hash,
                    "vote": True,
                    "epoch": 1,
                    "proposal_timestamp": proposal_ts,
                    "vote_signature": signature,
                },
                "timestamp": sp._utc_now(), "nonce": sp._nonce(),
            }, client_id, session)
            return sp.verify_message(response.decode(), session)["payload"]

        first = cast("client-v1", "VAL1")
        self.assertEqual(first["validator_count"], 3)
        self.assertEqual(first["quorum_threshold"], 2)
        self.assertFalse(first["quorum_reached"])
        second = cast("client-v2", "VAL2")
        self.assertTrue(second["quorum_reached"])
        self.assertEqual(second["status"], "ACCEPTED")


if __name__ == "__main__":
    unittest.main()
