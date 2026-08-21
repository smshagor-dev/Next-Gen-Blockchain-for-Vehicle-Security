"""v2.6+ permissioned wrapper around the hardened legacy sync transport."""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from permissioned_consensus import ConsensusError, PermissionedConsensusEngine, sign_vote
from replay_security import BoundedReplayCache
from sync_protocol_legacy import *
from sync_protocol_legacy import (
    SyncClient as _LegacySyncClient,
    SyncServer as _LegacySyncServer,
    _canonical_json,
    _claim_nonce,
    _derive_session_key,
    _handshake_auth_payload,
    _handshake_mac,
    _is_fresh_timestamp,
    _load_json_secret_map,
    _nonce,
    _parse_timestamp,
    _prune_replay_cache,
    _utc_now,
    _validate_secret_value,
)


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class SyncServer(_LegacySyncServer):
    """Sync server with fail-closed admission, voting, and bounded replay state."""

    def __init__(
        self,
        host: str = None,
        port: int = None,
        shared_key: str = None,
        authority_registry: Optional[Dict[str, str]] = None,
        vehicle_key_registry: Optional[Dict[str, str]] = None,
        validator_ids: Optional[List[str]] = None,
    ):
        super().__init__(
            host=host,
            port=port,
            shared_key=shared_key,
            authority_registry=authority_registry,
            vehicle_key_registry=vehicle_key_registry,
            validator_ids=validator_ids,
        )
        self.consensus_epoch = max(1, get_int("SMARTCAR_CONSENSUS_EPOCH", 1))
        self.consensus_quorum_numerator = max(1, get_int("SMARTCAR_CONSENSUS_QUORUM_NUMERATOR", 2))
        self.consensus_quorum_denominator = max(1, get_int("SMARTCAR_CONSENSUS_QUORUM_DENOMINATOR", 3))
        self.consensus_proposal_ttl_sec = max(3, get_int("SMARTCAR_CONSENSUS_PROPOSAL_TTL_SEC", 30))
        self.consensus_max_proposals = max(16, get_int("SMARTCAR_CONSENSUS_MAX_PROPOSALS", 4096))
        self.replay_cache_max_entries = max(64, get_int("SMARTCAR_SYNC_REPLAY_CACHE_MAX_ENTRIES", 4096))
        self.handshake_replay_cache_max_entries = max(
            64,
            get_int("SMARTCAR_SYNC_HANDSHAKE_REPLAY_CACHE_MAX_ENTRIES", 4096),
        )
        self._handshake_replay_cache = BoundedReplayCache(
            max_entries=self.handshake_replay_cache_max_entries
        )
        self._permissioned_consensus = None

    def _vehicle_secret(self, vehicle_id: str) -> str:
        # v2.6 requires explicit per-identity enrollment by default. A single
        # global PSK is retained only as an explicit lab migration mode.
        if self.vehicle_key_registry:
            secret = self.vehicle_key_registry.get(vehicle_id, "")
            if not secret:
                raise RuntimeError("UNREGISTERED_VEHICLE")
            return secret
        if _bool_env("SMARTCAR_SYNC_ALLOW_GLOBAL_PSK_ADMISSION", False):
            return self.shared_key
        raise RuntimeError("IDENTITY_ADMISSION_REGISTRY_REQUIRED")

    def _consensus_engine(self) -> PermissionedConsensusEngine:
        if self._permissioned_consensus is not None:
            return self._permissioned_consensus
        if not self.validator_ids:
            raise ConsensusError("VALIDATOR_SET_EMPTY")
        self._permissioned_consensus = PermissionedConsensusEngine(
            self.authority_registry,
            validator_ids=sorted(self.validator_ids),
            epoch=self.consensus_epoch,
            quorum_numerator=self.consensus_quorum_numerator,
            quorum_denominator=self.consensus_quorum_denominator,
            proposal_ttl_sec=self.consensus_proposal_ttl_sec,
            max_proposals=self.consensus_max_proposals,
        )
        return self._permissioned_consensus

    def rotate_consensus_epoch(
        self,
        new_epoch: int,
        authority_registry: Dict[str, str],
        validator_ids: Optional[List[str]] = None,
    ) -> Dict[str, object]:
        selected = set(validator_ids or authority_registry.keys())
        engine = self._consensus_engine()
        metadata = engine.rotate_epoch(new_epoch, authority_registry, selected)
        with self._lock:
            self.authority_registry = dict(authority_registry)
            self.authority_order = sorted(self.authority_registry)
            self.validator_ids = set(selected)
            self.consensus_epoch = int(new_epoch)
            self.vote_registry.clear()
        return metadata

    def consensus_metadata(self) -> Dict[str, object]:
        try:
            return self._consensus_engine().metadata()
        except ConsensusError as exc:
            return {
                "policy": "OMNIGUARD_PERMISSIONED_CONSENSUS_V2_6",
                "consensus_model": "permissioned_quorum",
                "configured": False,
                "reason": exc.reason,
                "secret_values_exposed": False,
            }

    def replay_security_metadata(self) -> Dict[str, object]:
        with self._lock:
            session_caches = [
                state.get("replay_cache")
                for state in self.clients.values()
                if isinstance(state.get("replay_cache"), BoundedReplayCache)
            ]
        return {
            "policy": "OMNIGUARD_BOUNDED_REPLAY_CACHE_V1",
            "session_cache_max_entries": self.replay_cache_max_entries,
            "handshake_cache": self._handshake_replay_cache.metadata(),
            "active_bounded_session_caches": len(session_caches),
            "session_saturation_rejections": sum(
                cache.saturation_rejections for cache in session_caches
            ),
            "evicts_live_nonces": False,
            "fail_closed_on_saturation": True,
        }

    def _process_message(self, msg: dict, client_id: str, session_key: str):
        mtype = msg.get("type")
        payload = msg.get("payload", {})
        if mtype not in {MessageType.VOTE_SUBMIT, MessageType.VOTE_TALLY_REQUEST}:
            response = super()._process_message(msg, client_id, session_key)
            if mtype == MessageType.HANDSHAKE and response:
                with self._lock:
                    state = self.clients.get(client_id)
                    if state is not None and not isinstance(
                        state.get("replay_cache"), BoundedReplayCache
                    ):
                        state["replay_cache"] = BoundedReplayCache(
                            state.get("replay_cache", {}),
                            max_entries=self.replay_cache_max_entries,
                        )
            return response

        if not session_key or not self._bound_vehicle(client_id):
            return None
        bound_vehicle = self._bound_vehicle(client_id)

        if mtype == MessageType.VOTE_SUBMIT:
            if not self._payload_matches_session(client_id, payload):
                return self._error("VEHICLE_IDENTITY_MISMATCH", session_key)
            claimed_voter = str(payload.get("voter_id", "")).strip()
            if claimed_voter and claimed_voter != bound_vehicle:
                return self._error("VOTER_IDENTITY_MISMATCH", session_key)
            if not self.validator_ids or bound_vehicle not in self.validator_ids:
                return self._error("VALIDATOR_NOT_AUTHORIZED", session_key)
            try:
                tally = self._consensus_engine().submit_vote(
                    proposal_id=str(payload.get("proposal_id", "")),
                    proposal_hash=str(payload.get("proposal_hash", "")),
                    voter_id=bound_vehicle,
                    vote=bool(payload.get("vote", False)),
                    epoch=int(payload.get("epoch", 0)),
                    proposal_timestamp=str(payload.get("proposal_timestamp", "")),
                    vote_signature=str(payload.get("vote_signature", "")),
                    reason=str(payload.get("reason", "")),
                )
            except (ConsensusError, TypeError, ValueError) as exc:
                reason = exc.reason if isinstance(exc, ConsensusError) else "INVALID_VOTE_PAYLOAD"
                return self._error(reason, session_key)

            # Compatibility mirror: only verified, immutable votes are exposed.
            with self._lock:
                self.vote_registry[str(tally["proposal_id"])] = {
                    validator_id: dict(vote_data)
                    for validator_id, vote_data in dict(tally.get("votes", {})).items()
                }
            response = dict(tally)
            response.update({"acknowledged": True, "voter_id": bound_vehicle})
            return create_message(MessageType.VOTE_TALLY_RESPONSE, response, session_key)

        proposal_id = str(payload.get("proposal_id", "")).strip()
        try:
            epoch = payload.get("epoch")
            tally = self._consensus_engine().tally(
                proposal_id,
                epoch=None if epoch in (None, "") else int(epoch),
            )
        except (ConsensusError, TypeError, ValueError) as exc:
            reason = exc.reason if isinstance(exc, ConsensusError) else "INVALID_TALLY_REQUEST"
            return self._error(reason, session_key)
        return create_message(MessageType.VOTE_TALLY_RESPONSE, tally, session_key)


class SyncClient(_LegacySyncClient):
    """Rotation/epoch-aware client with signed voting and bounded replay state."""

    def __init__(self, *args, validator_key: str = None, consensus_epoch: int = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.validator_key = str(validator_key or "")
        self.consensus_epoch = max(
            1,
            int(consensus_epoch if consensus_epoch is not None else get_int("SMARTCAR_CONSENSUS_EPOCH", 1)),
        )
        self.replay_cache_max_entries = max(64, get_int("SMARTCAR_SYNC_REPLAY_CACHE_MAX_ENTRIES", 4096))
        self._replay_cache = BoundedReplayCache(
            self._replay_cache,
            max_entries=self.replay_cache_max_entries,
        )

    def submit_vote(
        self,
        proposal_id: str,
        voter_id: str,
        vote: bool,
        reason: str = "",
        *,
        proposal_hash: str,
        epoch: int = None,
        proposal_timestamp: str = None,
        validator_key: str = None,
    ):
        if not self._connected:
            return None
        if voter_id and voter_id != self.vehicle_id:
            raise ValueError("voter_id must match the authenticated vehicle identity")
        effective_epoch = self.consensus_epoch if epoch is None else int(epoch)
        timestamp = str(proposal_timestamp or _utc_now())
        key = str(validator_key or self.validator_key)
        signature = sign_vote(
            proposal_id,
            proposal_hash,
            self.vehicle_id,
            bool(vote),
            effective_epoch,
            timestamp,
            key,
        )
        return self._send_recv(
            create_message(
                MessageType.VOTE_SUBMIT,
                {
                    "proposal_id": proposal_id,
                    "proposal_hash": proposal_hash,
                    "voter_id": self.vehicle_id,
                    "vehicle_id": self.vehicle_id,
                    "vote": bool(vote),
                    "reason": reason,
                    "epoch": effective_epoch,
                    "proposal_timestamp": timestamp,
                    "vote_signature": signature,
                },
                self.session_key,
            )
        )

    def request_vote_tally(self, proposal_id: str, epoch: int = None):
        if not self._connected:
            return None
        return self._send_recv(
            create_message(
                MessageType.VOTE_TALLY_REQUEST,
                {
                    "proposal_id": proposal_id,
                    "epoch": self.consensus_epoch if epoch is None else int(epoch),
                },
                self.session_key,
            )
        )
