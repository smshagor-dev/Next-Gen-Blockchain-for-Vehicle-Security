"""Simulation-only independent checkpoint issuer with atomic, crash-recoverable state.

Trust boundary: this process and its directory/key must be independently controlled.
Not blockchain finality, TPM monotonic storage, or resistance to host rollback.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path

DOMAIN = "OMNIGUARD_EXTERNAL_CHECKPOINT_V1"

class CheckpointRefused(ValueError):
    pass

def _tip(tip):
    if not isinstance(tip, str) or len(tip) != 64:
        raise CheckpointRefused("invalid tip")
    try:
        bytes.fromhex(tip)
    except ValueError as exc:
        raise CheckpointRefused("invalid tip") from exc
    return tip.lower()

def _message(vehicle, height, tip, revision):
    return json.dumps([DOMAIN, vehicle, height, tip, revision],
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")

class IndependentCheckpointIssuer:
    """Append-only observed-prefix checkpoint issuer, for isolated simulation.

    A caller supplies a verified sequence of block hashes, not an unverified
    single tip. The issuer detects divergence against its own durable pins.
    Caller MUST validate full Go block hashes/links before invoking issue().
    """

    def __init__(self, directory, vehicle, key):
        if not isinstance(vehicle, str) or not vehicle:
            raise CheckpointRefused("invalid vehicle")
        if not isinstance(key, bytes) or len(key) < 32:
            raise CheckpointRefused("invalid issuer key")
        self.directory = Path(directory)
        self.vehicle = vehicle
        self.key = key
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / (hashlib.sha256(vehicle.encode()).hexdigest() + ".json")

    def _load(self):
        if not self.path.exists():
            return {"vehicle": self.vehicle, "revision": 0, "pins": []}
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CheckpointRefused("unreadable issuer state") from exc
        if (not isinstance(state, dict) or set(state) != {"vehicle", "revision", "pins"}
            or state["vehicle"] != self.vehicle or type(state["revision"]) is not int
            or state["revision"] < 1 or not isinstance(state["pins"], list)
            or len(state["pins"]) < 1 or
            any(not isinstance(x, str) or _tip(x) != x for x in state["pins"])):
            raise CheckpointRefused("invalid issuer state")
        return state

    def issue(self, verified_block_hashes):
        # Requires single-writer ownership of the issuer directory; no locking
        # is claimed. Do not expose this method to an untrusted TCP endpoint.
        hashes = [_tip(x) for x in verified_block_hashes]
        if not hashes:
            raise CheckpointRefused("empty chain")
        state = self._load()
        old = state["pins"]
        if len(hashes) < len(old):
            raise CheckpointRefused("issuer observed truncation")
        if hashes[:len(old)] != old:
            raise CheckpointRefused("issuer observed rewritten prefix")
        if hashes != old:
            state = {"vehicle": self.vehicle, "revision": state["revision"] + 1, "pins": hashes}
            self._atomic_save(state)
        # Repeated unchanged chain must not consume a revision.
        revision = state["revision"]
        item = {"vehicle_id": self.vehicle, "height": len(hashes),
                "tip_hash": hashes[-1], "revision": revision}
        item["mac"] = hmac.new(self.key, _message(self.vehicle, len(hashes),
                                                 hashes[-1], revision),
                               hashlib.sha256).hexdigest()
        return item

    def _atomic_save(self, state):
        tmp = self.path.with_suffix(".pending")
        payload = json.dumps(state, separators=(",", ":"), sort_keys=True).encode()
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.path)
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
