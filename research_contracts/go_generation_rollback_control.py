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
