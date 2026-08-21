"""Permissioned epoch-scoped consensus for OmniGuard V2X.

This module hardens validator membership and vote handling. It does not claim
Byzantine fault tolerance against a sufficiently large authorized coalition.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, Mapping, Optional


VOTE_DOMAIN = "OMNIGUARD_PERMISSIONED_VOTE_V1"
PROPOSAL_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ConsensusError(RuntimeError):
    """Fail-closed consensus validation error with a stable reason code."""

    def __init__(self, reason: str):
        self.reason = str(reason)
        super().__init__(self.reason)


def _parse_timestamp(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _canonical_vote_message(
    proposal_id: str,
    proposal_hash: str,
    voter_id: str,
    vote: bool,
    epoch: int,
    proposal_timestamp: str,
) -> bytes:
    fields = [
        VOTE_DOMAIN,
        str(epoch),
        str(proposal_id),
        str(proposal_hash).lower(),
        str(voter_id),
        "1" if bool(vote) else "0",
        str(proposal_timestamp),
    ]
    return "\n".join(fields).encode("utf-8")


def sign_vote(
    proposal_id: str,
    proposal_hash: str,
    voter_id: str,
    vote: bool,
    epoch: int,
    proposal_timestamp: str,
    validator_key: str,
) -> str:
    key = str(validator_key or "")
    if len(key) < 32:
        raise ValueError("validator signing key must contain at least 32 characters")
    return hmac.new(
        key.encode("utf-8"),
        _canonical_vote_message(
            proposal_id,
            proposal_hash,
            voter_id,
            vote,
            epoch,
            proposal_timestamp,
        ),
        hashlib.sha256,
    ).hexdigest()


def verify_vote_signature(
    proposal_id: str,
    proposal_hash: str,
    voter_id: str,
    vote: bool,
    epoch: int,
    proposal_timestamp: str,
    vote_signature: str,
    validator_key: str,
) -> bool:
    try:
        received = str(vote_signature or "")
        if not HEX64_RE.fullmatch(received):
            return False
        expected = sign_vote(
            proposal_id,
            proposal_hash,
            voter_id,
            vote,
            epoch,
            proposal_timestamp,
            validator_key,
        )
        return hmac.compare_digest(received.lower(), expected)
    except Exception:
        return False


@dataclass
class ProposalState:
    proposal_id: str
    proposal_hash: str
    epoch: int
    proposal_timestamp: str
    votes: Dict[str, Dict[str, object]] = field(default_factory=dict)
    status: str = "PENDING"


class PermissionedConsensusEngine:
    """Epoch-scoped fixed-membership quorum engine.

    Quorum is computed against the complete configured validator set, not only
    validators that happened to vote. One validator can cast at most one vote
    for a proposal in an epoch.
    """

    def __init__(
        self,
        validator_keys: Mapping[str, str],
        *,
        validator_ids: Optional[Iterable[str]] = None,
        epoch: int = 1,
        quorum_numerator: int = 2,
        quorum_denominator: int = 3,
        proposal_ttl_sec: int = 30,
        max_proposals: int = 4096,
    ):
        self._lock = threading.RLock()
        self.quorum_numerator = max(1, int(quorum_numerator))
        self.quorum_denominator = max(1, int(quorum_denominator))
        if self.quorum_numerator > self.quorum_denominator:
            raise ValueError("quorum numerator cannot exceed denominator")
        self.proposal_ttl_sec = max(3, int(proposal_ttl_sec))
        self.max_proposals = max(16, int(max_proposals))
        self.epoch = max(1, int(epoch))
        self.proposals: Dict[str, ProposalState] = {}
        self._configure_validators(validator_keys, validator_ids)

    def _configure_validators(
        self,
        validator_keys: Mapping[str, str],
        validator_ids: Optional[Iterable[str]],
    ) -> None:
        keys = {str(k).strip(): str(v) for k, v in dict(validator_keys or {}).items() if str(k).strip()}
        selected = {str(v).strip() for v in (validator_ids or keys.keys()) if str(v).strip()}
        if not selected:
            raise ConsensusError("VALIDATOR_SET_EMPTY")
        missing = sorted(v for v in selected if len(keys.get(v, "")) < 32)
        if missing:
            raise ConsensusError("VALIDATOR_KEY_NOT_CONFIGURED")
        self.validator_ids = frozenset(selected)
        self.validator_keys = {validator_id: keys[validator_id] for validator_id in selected}

    @property
    def validator_count(self) -> int:
        return len(self.validator_ids)

    @property
    def quorum_threshold(self) -> int:
        return max(
            1,
            math.ceil(
                self.validator_count * self.quorum_numerator / self.quorum_denominator
            ),
        )

    def _validate_proposal_fields(
        self,
        proposal_id: str,
        proposal_hash: str,
        epoch: int,
        proposal_timestamp: str,
    ) -> tuple[str, str, datetime]:
        proposal_id = str(proposal_id or "").strip()
        proposal_hash = str(proposal_hash or "").strip().lower()
        if not PROPOSAL_ID_RE.fullmatch(proposal_id):
            raise ConsensusError("INVALID_PROPOSAL_ID")
        if not HEX64_RE.fullmatch(proposal_hash):
            raise ConsensusError("INVALID_PROPOSAL_HASH")
        if int(epoch) != self.epoch:
            raise ConsensusError("CONSENSUS_EPOCH_MISMATCH")
        parsed = _parse_timestamp(proposal_timestamp)
        if parsed is None:
            raise ConsensusError("INVALID_PROPOSAL_TIMESTAMP")
        skew = abs((datetime.now(timezone.utc) - parsed).total_seconds())
        if skew > self.proposal_ttl_sec:
            raise ConsensusError("STALE_PROPOSAL")
        return proposal_id, proposal_hash, parsed

    def submit_vote(
        self,
        *,
        proposal_id: str,
        proposal_hash: str,
        voter_id: str,
        vote: bool,
        epoch: int,
        proposal_timestamp: str,
        vote_signature: str,
        reason: str = "",
    ) -> Dict[str, object]:
        voter_id = str(voter_id or "").strip()
        if voter_id not in self.validator_ids:
            raise ConsensusError("VALIDATOR_NOT_AUTHORIZED")
        proposal_id, proposal_hash, _ = self._validate_proposal_fields(
            proposal_id, proposal_hash, epoch, proposal_timestamp
        )
        validator_key = self.validator_keys.get(voter_id, "")
        if not verify_vote_signature(
            proposal_id,
            proposal_hash,
            voter_id,
            bool(vote),
            self.epoch,
            proposal_timestamp,
            vote_signature,
            validator_key,
        ):
            raise ConsensusError("INVALID_VOTE_SIGNATURE")

        with self._lock:
            state = self.proposals.get(proposal_id)
            if state is None:
                if len(self.proposals) >= self.max_proposals:
                    raise ConsensusError("PROPOSAL_CAPACITY_EXCEEDED")
                state = ProposalState(
                    proposal_id=proposal_id,
                    proposal_hash=proposal_hash,
                    epoch=self.epoch,
                    proposal_timestamp=str(proposal_timestamp),
                )
                self.proposals[proposal_id] = state
            else:
                if state.epoch != self.epoch:
                    raise ConsensusError("CONSENSUS_EPOCH_MISMATCH")
                if not hmac.compare_digest(state.proposal_hash, proposal_hash):
                    raise ConsensusError("PROPOSAL_HASH_MISMATCH")
                if state.status != "PENDING":
                    raise ConsensusError("PROPOSAL_FINALIZED")
                if voter_id in state.votes:
                    raise ConsensusError("DUPLICATE_VOTE")

            state.votes[voter_id] = {
                "vote": bool(vote),
                "reason": str(reason)[:512],
                "epoch": self.epoch,
                "proposal_hash": proposal_hash,
                "signature_verified": True,
            }
            self._update_status(state)
            return self._tally_locked(state)

    def _update_status(self, state: ProposalState) -> None:
        yes_votes = sum(1 for value in state.votes.values() if value.get("vote") is True)
        no_votes = len(state.votes) - yes_votes
        threshold = self.quorum_threshold
        if yes_votes >= threshold:
            state.status = "ACCEPTED"
            return
        # Once enough no votes exist that quorum can no longer be reached, freeze reject.
        if no_votes > self.validator_count - threshold:
            state.status = "REJECTED"

    def _tally_locked(self, state: ProposalState) -> Dict[str, object]:
        yes_votes = sum(1 for value in state.votes.values() if value.get("vote") is True)
        no_votes = len(state.votes) - yes_votes
        return {
            "proposal_id": state.proposal_id,
            "proposal_hash": state.proposal_hash,
            "epoch": state.epoch,
            "status": state.status,
            "yes_votes": yes_votes,
            "no_votes": no_votes,
            "total_votes": len(state.votes),
            "validator_count": self.validator_count,
            "quorum_threshold": self.quorum_threshold,
            "quorum_reached": state.status == "ACCEPTED",
            "majority_accept": state.status == "ACCEPTED",
            "votes": {key: dict(value) for key, value in state.votes.items()},
        }

    def tally(self, proposal_id: str, *, epoch: Optional[int] = None) -> Dict[str, object]:
        proposal_id = str(proposal_id or "").strip()
        if not PROPOSAL_ID_RE.fullmatch(proposal_id):
            raise ConsensusError("INVALID_PROPOSAL_ID")
        if epoch is not None and int(epoch) != self.epoch:
            raise ConsensusError("CONSENSUS_EPOCH_MISMATCH")
        with self._lock:
            state = self.proposals.get(proposal_id)
            if state is None:
                return {
                    "proposal_id": proposal_id,
                    "epoch": self.epoch,
                    "status": "UNKNOWN",
                    "yes_votes": 0,
                    "no_votes": 0,
                    "total_votes": 0,
                    "validator_count": self.validator_count,
                    "quorum_threshold": self.quorum_threshold,
                    "quorum_reached": False,
                    "majority_accept": False,
                    "votes": {},
                }
            return self._tally_locked(state)

    def rotate_epoch(
        self,
        new_epoch: int,
        validator_keys: Mapping[str, str],
        validator_ids: Optional[Iterable[str]] = None,
    ) -> Dict[str, object]:
        new_epoch = int(new_epoch)
        with self._lock:
            if new_epoch <= self.epoch:
                raise ConsensusError("EPOCH_NOT_MONOTONIC")
            self._configure_validators(validator_keys, validator_ids)
            self.epoch = new_epoch
            self.proposals.clear()
            return self.metadata()

    def metadata(self) -> Dict[str, object]:
        with self._lock:
            pending = sum(1 for state in self.proposals.values() if state.status == "PENDING")
            finalized = len(self.proposals) - pending
        return {
            "policy": "OMNIGUARD_PERMISSIONED_CONSENSUS_V2_6",
            "consensus_model": "permissioned_quorum",
            "epoch": self.epoch,
            "validator_count": self.validator_count,
            "validator_ids": sorted(self.validator_ids),
            "quorum_numerator": self.quorum_numerator,
            "quorum_denominator": self.quorum_denominator,
            "quorum_threshold": self.quorum_threshold,
            "proposal_ttl_sec": self.proposal_ttl_sec,
            "pending_proposals": pending,
            "finalized_proposals": finalized,
            "validator_membership_enforced": True,
            "vote_signature_required": True,
            "duplicate_vote_rejected": True,
            "quorum_basis": "configured_validator_set",
            "secret_values_exposed": False,
        }
