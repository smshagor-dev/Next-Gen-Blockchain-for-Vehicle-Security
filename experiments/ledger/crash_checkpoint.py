"""Crash-consistent local ledger snapshot checkpoint *research harness*.

The authenticated ledger verifier remains the authority on block correctness.
This module only atomically stores a hash-bound checkpoint of an ALREADY
verified snapshot. It is not a consensus protocol, distributed finality,
trusted monotonic counter, HSM, or protection against host rollback.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

from ledger_integrity import GoLedgerSnapshotVerifier, LedgerIntegrityError

SCHEMA = "OMNIGUARD_LEDGER_CHECKPOINT_V1"
MAX_BYTES = 16 * 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read(path: Path) -> dict | None:
    try:
        with path.open("rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(raw) > MAX_BYTES:
        raise LedgerIntegrityError("checkpoint exceeds byte limit")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise LedgerIntegrityError("checkpoint truncated or malformed") from exc
    if not isinstance(data, dict):
        raise LedgerIntegrityError("checkpoint must be a JSON object")
    return data


def _validate(data: dict, *, vehicle_id: str, generation: str) -> dict:
    if set(data) != {"schema", "vehicle_id", "generation", "height",
                     "tip_hash", "chain_sha256", "snapshot", "envelope_sha256"}:
        raise LedgerIntegrityError("checkpoint schema mismatch")
    envelope = {k: v for k, v in data.items() if k != "envelope_sha256"}
    if data["schema"] != SCHEMA or data["vehicle_id"] != vehicle_id:
        raise LedgerIntegrityError("checkpoint identity mismatch")
    if data["generation"] != generation:
        raise LedgerIntegrityError("checkpoint service generation mismatch")
    if not isinstance(data["height"], int) or isinstance(data["height"], bool):
        raise LedgerIntegrityError("checkpoint height invalid")
    if not isinstance(data["snapshot"], list) or not data["snapshot"]:
        raise LedgerIntegrityError("checkpoint snapshot missing")
    if data["height"] != len(data["snapshot"]) - 1:
        raise LedgerIntegrityError("checkpoint height mismatch")
    if data["tip_hash"] != data["snapshot"][-1].get("block_hash"):
        raise LedgerIntegrityError("checkpoint tip mismatch")
    if data["chain_sha256"] != _hash(data["snapshot"]):
        raise LedgerIntegrityError("checkpoint chain hash mismatch")
    if data["envelope_sha256"] != _hash(envelope):
        raise LedgerIntegrityError("checkpoint envelope hash mismatch")
    verifier = GoLedgerSnapshotVerifier(vehicle_id)
    verifier.verify_and_track(data["snapshot"], generation)
    return data


def _fsync_directory(directory: Path) -> None:
    # Directory durability is required for atomic rename on POSIX.
    if os.name == "nt":
        return  # Windows directory fsync is not exposed by portable Python.
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class CrashCheckpointStore:
    """Single-writer, local crash-recovery harness; not live Go persistence.

    Caller MUST serialize writers with an external lock. Checkpoints have no
    host-rollback resistance: a copied older valid file can replace a newer
    checkpoint unless independently pinned to a trusted external anchor.
    """

    def __init__(self, path: Path, *, vehicle_id: str, generation: str,
                 failpoint: Callable[[str], None] | None = None):
        self.path = Path(path)
        self.vehicle_id = vehicle_id
        self.generation = generation
        if not vehicle_id or not generation:
            raise ValueError("vehicle and authenticated service generation required")
        self.failpoint = failpoint or (lambda stage: None)

    def load(self) -> dict | None:
        data = _read(self.path)
        if data is None:
            return None
        return _validate(data, vehicle_id=self.vehicle_id, generation=self.generation)

    def commit(self, snapshot: list[Mapping[str, Any]]) -> dict:
        # Validate the incoming chain independently BEFORE touching the disk.
        snapshot = list(snapshot)
        verifier = GoLedgerSnapshotVerifier(self.vehicle_id)
        verifier.verify_and_track(snapshot, self.generation)
        previous = self.load()
        if previous is not None:
            old = previous["snapshot"]
            if len(snapshot) < len(old):
                raise LedgerIntegrityError("checkpoint chain height regressed")
            for index, block in enumerate(old):
                if _hash(block) != _hash(snapshot[index]):
                    raise LedgerIntegrityError(f"checkpoint history changed at block {index}")
        envelope = {
            "schema": SCHEMA, "vehicle_id": self.vehicle_id,
            "generation": self.generation, "height": len(snapshot) - 1,
            "tip_hash": snapshot[-1]["block_hash"],
            "chain_sha256": _hash(snapshot), "snapshot": snapshot,
        }
        envelope["envelope_sha256"] = _hash(envelope)
        encoded = _canonical(envelope) + b"\n"
        if len(encoded) > MAX_BYTES:
            raise LedgerIntegrityError("checkpoint exceeds byte limit")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix="." + self.path.name + ".",
                suffix=".tmp", dir=self.path.parent, delete=False,
            ) as f:
                tmp_name = f.name
                f.write(encoded)
                f.flush()
                os.fsync(f.fileno())
            self.failpoint("after_temp_fsync")
            os.replace(tmp_name, self.path)
            tmp_name = None
            self.failpoint("after_replace_before_directory_fsync")
            _fsync_directory(self.path.parent)
            self.failpoint("after_directory_fsync")
        finally:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
        return envelope
