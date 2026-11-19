"""Experimental durable replay ledger. NOT an actuator authorization system.
A privileged host can roll back a valid snapshot; local digest is not a MAC.
"""
import hashlib
import json
import os
import tempfile
from pathlib import Path

class StateError(ValueError):
    pass

class DurableAdmissionState:
    def __init__(self, path, *, max_entries=10000):
        self.path = Path(path)
        if type(max_entries) is not int or not 1 <= max_entries <= 100000:
            raise StateError("invalid capacity")
        self.max_entries = max_entries
        self.nonces = set()
        self.admitted = set()
        if self.path.exists() or self.path.is_symlink():
            self._load()

    def _load(self):
        if self.path.is_symlink() or not self.path.is_file() or self.path.stat().st_size > 2000000:
            raise StateError("unsafe state file")
        try:
            obj = json.loads(self.path.read_bytes())
            payload = obj["payload"]
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            if obj["sha256"] != hashlib.sha256(canonical).hexdigest():
                raise StateError("integrity mismatch")
            if payload["version"] != 1:
                raise StateError("unsupported version")
            for field in ("nonces", "admitted"):
                values = payload[field]
                if not isinstance(values, list) or len(values) > self.max_entries or len(values) != len(set(values)) or any(type(x) is not str or not 1 <= len(x) <= 256 for x in values):
                    raise StateError("invalid entries")
            self.nonces = set(payload["nonces"])
            self.admitted = set(payload["admitted"])
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise StateError("invalid durable state") from exc

    def record(self, nonce, incident):
        if any(type(x) is not str or not 1 <= len(x) <= 256 for x in (nonce, incident)):
            raise StateError("invalid identifier")
        if nonce in self.nonces or incident in self.admitted:
            return False
        if len(self.nonces) >= self.max_entries or len(self.admitted) >= self.max_entries:
            raise StateError("capacity exhausted")
        nonces = self.nonces | {nonce}
        admitted = self.admitted | {incident}
        payload = {"version": 1, "nonces": sorted(nonces), "admitted": sorted(admitted)}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        data = json.dumps({"payload": payload, "sha256": hashlib.sha256(canonical).hexdigest()}, sort_keys=True).encode()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=".admission-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp, self.path)
            dir_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        self.nonces, self.admitted = nonces, admitted
        return True
