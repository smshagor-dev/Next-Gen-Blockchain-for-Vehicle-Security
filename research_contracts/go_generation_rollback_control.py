"""Non-actuating, process-local negative control for Go ledger generation rollback.

An authenticated service generation is an identity hint, not an external finality
certificate. This monitor intentionally does not reset observed prefix commitments
when the generation changes. Process restart still loses its pins; external
durable/independent checkpoints are required for rollback resistance.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from ledger_integrity import GoLedgerSnapshotVerifier, LedgerIntegrityError


def _fingerprint(block):
    return hashlib.sha256(json.dumps(
        block, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


class CrossGenerationPrefixMonitor:
    """Detect truncation or mutation across Go service generation changes.

    This is a local observer, not a consensus proof or authenticated checkpoint.
    The underlying Go verifier checks hashes and links; prefix pins prevent its
    documented generation-reset behavior from silently forgetting history.
    """

    def __init__(self, vehicle_id):
        self.verifier = GoLedgerSnapshotVerifier(vehicle_id)
        self._pins = {}
        self._last_generation = None

    def verify(self, blocks, generation):
        blocks = list(blocks)
        if not isinstance(generation, str) or not generation:
            raise LedgerIntegrityError("missing authenticated generation")
        if len(blocks) < len(self._pins):
            raise LedgerIntegrityError("cross-generation ledger truncation")
        candidate = {}
        for i, block in enumerate(blocks):
            if not isinstance(block, Mapping):
                raise LedgerIntegrityError("ledger block must be a mapping")
            digest = _fingerprint(block)
            if i in self._pins and self._pins[i] != digest:
                raise LedgerIntegrityError("cross-generation committed prefix mutation")
            candidate[i] = digest
        # Only advance pins after independent Go hash/link validation succeeds.
        self.verifier.verify_and_track(blocks, generation)
        self._pins.update(candidate)
        self._last_generation = generation
        return True

    @property
    def observed_blocks(self):
        return len(self._pins)


# Negative-control protocol: the verifier does not own or update the anchor.
# The signed checkpoint must arrive through an independently trusted channel.
# An attacker who can replace both the checkpoint and its key is out of scope.
import hmac


def checkpoint_message(vehicle_id, height, tip_hash, revision):
    """Canonical, domain-separated commitment; revision is external monotonic state."""
    if not isinstance(vehicle_id, str) or not vehicle_id:
        raise LedgerIntegrityError("invalid checkpoint vehicle")
    if type(height) is not int or height < 1:
        raise LedgerIntegrityError("invalid checkpoint height")
    if type(revision) is not int or revision < 1:
        raise LedgerIntegrityError("invalid checkpoint revision")
    if not isinstance(tip_hash, str) or len(tip_hash) != 64:
        raise LedgerIntegrityError("invalid checkpoint tip")
    try:
        bytes.fromhex(tip_hash)
    except ValueError as exc:
        raise LedgerIntegrityError("invalid checkpoint tip") from exc
    return json.dumps(
        ["OMNIGUARD_EXTERNAL_CHECKPOINT_V1", vehicle_id, height,
         tip_hash.lower(), revision],
        separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def verify_external_checkpoint(blocks, checkpoint, mac_key, expected_vehicle,
                               minimum_revision=1):
    """Check a separately authenticated anchor against a complete Go ledger.

    This does NOT establish consensus finality, independent key custody,
    trustworthy revision persistence, or hardware safety. The caller must pin
    minimum_revision in independently controlled monotonic storage.
    """
    if not isinstance(checkpoint, Mapping):
        raise LedgerIntegrityError("checkpoint must be a mapping")
    if not isinstance(mac_key, bytes) or len(mac_key) < 32:
        raise LedgerIntegrityError("checkpoint verification key unavailable")
    if type(minimum_revision) is not int or minimum_revision < 1:
        raise LedgerIntegrityError("invalid trusted revision floor")
    if set(checkpoint) != {"vehicle_id", "height", "tip_hash", "revision", "mac"}:
        raise LedgerIntegrityError("unexpected checkpoint fields")
    msg = checkpoint_message(checkpoint["vehicle_id"], checkpoint["height"],
                             checkpoint["tip_hash"], checkpoint["revision"])
    if checkpoint["vehicle_id"] != expected_vehicle:
        raise LedgerIntegrityError("checkpoint vehicle mismatch")
    if checkpoint["revision"] < minimum_revision:
        raise LedgerIntegrityError("checkpoint revision rollback")
    mac = checkpoint["mac"]
    if not isinstance(mac, str) or len(mac) != 64:
        raise LedgerIntegrityError("invalid checkpoint MAC")
    expected = hmac.new(mac_key, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac.lower(), expected):
        raise LedgerIntegrityError("checkpoint authentication failed")
    blocks = list(blocks)
    if len(blocks) < checkpoint["height"]:
        raise LedgerIntegrityError("ledger shorter than authenticated checkpoint")
    # Validate the full supplied chain before accepting an anchored prefix.
    GoLedgerSnapshotVerifier(expected_vehicle).verify_and_track(blocks, "checkpoint-check")
    if blocks[checkpoint["height"] - 1]["block_hash"].lower() != checkpoint["tip_hash"].lower():
        raise LedgerIntegrityError("authenticated checkpoint tip mismatch")
    return True
