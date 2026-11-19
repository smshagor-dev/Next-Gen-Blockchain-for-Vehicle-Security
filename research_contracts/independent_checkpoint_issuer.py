"""Simulation-only independent checkpoint issuer with atomic, crash-recoverable state.

Trust boundary: this process and its directory/key must be independently controlled.
Not blockchain finality, TPM monotonic storage, or resistance to host rollback.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # No portable locking guarantee on this platform.
    fcntl = None

DOMAIN = "OMNIGUARD_EXTERNAL_CHECKPOINT_V1"
# Simulation guardrail: reject oversized/unbounded supplied histories before persistence.
MAX_CHECKPOINT_BLOCKS = 100_000
# Canonical state is a compact JSON array of 64-character hex digests.
# Bound disk-originated input separately from caller-originated iterators.
MAX_CHECKPOINT_STATE_BYTES = MAX_CHECKPOINT_BLOCKS * 70 + 1024

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
        if not self.path.exists() and not self.path.is_symlink():
            return {"vehicle": self.vehicle, "revision": 0, "pins": []}
        # Refuse symlinks, special files, and oversized on-disk state before
        # decoding. An attacker-controlled FIFO could otherwise block read_text()
        # indefinitely, and an oversized JSON array could exhaust memory.
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(self.path, flags)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise CheckpointRefused("issuer state is not a regular file")
                # A writable or hardlinked state file is not an independent trust anchor.
                # Validate the opened inode, not only the path, before parsing it.
                if (info.st_uid != os.getuid() or info.st_nlink != 1
                    or (info.st_mode & 0o077)):
                    raise CheckpointRefused("unsafe issuer state metadata")
                if info.st_size > MAX_CHECKPOINT_STATE_BYTES:
                    raise CheckpointRefused("issuer state exceeds byte limit")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    raw = stream.read(MAX_CHECKPOINT_STATE_BYTES + 1)
                if len(raw) > MAX_CHECKPOINT_STATE_BYTES:
                    raise CheckpointRefused("issuer state exceeds byte limit")
            finally:
                os.close(fd)
            state = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise CheckpointRefused("unreadable issuer state") from exc
        if (not isinstance(state, dict) or set(state) != {"vehicle", "revision", "pins"}
            or state["vehicle"] != self.vehicle or type(state["revision"]) is not int
            or state["revision"] < 1 or not isinstance(state["pins"], list)
            or not 1 <= len(state["pins"]) <= MAX_CHECKPOINT_BLOCKS
            or any(not isinstance(x, str) or _tip(x) != x for x in state["pins"])):
            raise CheckpointRefused("invalid issuer state")
        return state

    @contextmanager
    def _exclusive_writer(self):
        # POSIX advisory lock: all issuers must cooperate and share this directory.
        # A separate persistent lock inode avoids rename-induced lock bypass.
        if fcntl is None:
            raise CheckpointRefused("exclusive locking unavailable on this platform")
        lock_path = self.path.with_suffix(".lock")
        # A symlinked or replaced lock inode can silently split the writer
        # serialization domain. Refuse rather than locking an attacker target.
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if not hasattr(os, "O_NOFOLLOW"):
            raise CheckpointRefused("safe lock-file opening unavailable")
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise CheckpointRefused("unsafe issuer lock path") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or (info.st_mode & 0o077)):
                raise CheckpointRefused("unsafe issuer lock metadata")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CheckpointRefused("concurrent issuer writer") from exc
            # Check path identity after acquiring the lock. Directory write
            # access must still be independently restricted by deployment.
            try:
                current = os.lstat(lock_path)
            except OSError as exc:
                raise CheckpointRefused("issuer lock path disappeared") from exc
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise CheckpointRefused("issuer lock inode replaced")
            yield
        finally:
            os.close(fd)

    def issue(self, verified_block_hashes):
        # Lock covers state read, prefix comparison, durable write and response.
        # Do not expose this method to an untrusted TCP endpoint.
        with self._exclusive_writer():
            return self._issue_locked(verified_block_hashes)

    def _issue_locked(self, verified_block_hashes):
        # Explicitly bound iterator consumption: a malicious/infinite generator must
        # not exhaust issuer memory or hold the exclusive lock indefinitely.
        if isinstance(verified_block_hashes, (str, bytes)):
            raise CheckpointRefused("invalid chain sequence")
        try:
            iterator = iter(verified_block_hashes)
        except TypeError as exc:
            raise CheckpointRefused("invalid chain sequence") from exc
        hashes = []
        for item in iterator:
            if len(hashes) == MAX_CHECKPOINT_BLOCKS:
                raise CheckpointRefused("chain exceeds checkpoint block limit")
            hashes.append(_tip(item))
        if not hashes:
            raise CheckpointRefused("empty chain")
        # A SIGKILL before os.replace may leave an exclusive-create .pending file.
        # Only the locked issuer may discard it; the committed .json remains
        # authoritative. Never promote unverified pending bytes into state.
        pending = self.path.with_suffix(".pending")
        if pending.is_symlink() or pending.exists():
            try:
                pending.unlink()
                directory_fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as exc:
                raise CheckpointRefused("cannot clear stale pending state") from exc
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
