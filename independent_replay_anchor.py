"""Experimental independent admission anchor, not a production trust root.

The anchor must be a separate, non-rollbackable authority with atomic
reserve(device, nonce) semantics. An in-process set or a second local SQLite
file DOES NOT satisfy that requirement. Reservation precedes SQLite admission:
crashes may reject legitimate retries, but cannot authorize a duplicate
while the external anchor remains intact.
"""
from __future__ import annotations

import hashlib
import sqlite3
from typing import Protocol


class IndependentNonceAnchor(Protocol):
    def reserve(self, device: str, nonce_digest: bytes) -> bool:
        """Atomically return True only for the first reservation."""


class AnchoredNonceAdmission:
    def __init__(self, store, anchor: IndependentNonceAnchor):
        self.store = store
        self.anchor = anchor

    def claim(self, device: str, nonce: str, *, window_seconds: int):
        if not isinstance(device, str) or not device:
            raise ValueError("device must be a nonempty string")
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a nonempty string")
        if type(window_seconds) is not int or window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        # Domain separation and length-prefixing avoid ambiguous concatenations.
        device_bytes = device.encode("utf-8")
        nonce_bytes = nonce.encode("utf-8")
        material = (b"omni-v2x-anchor-v1\x00"
                    + len(device_bytes).to_bytes(4, "big") + device_bytes
                    + len(nonce_bytes).to_bytes(4, "big") + nonce_bytes)
        digest = hashlib.sha256(material).digest()
        # No fall-through on anchor failure or timeout: caller must fail closed.
        if not self.anchor.reserve(device, digest):
            return "HW_ANCHOR_REPLAY_DETECTED"
        # Reserve-first creates an availability trade-off: a failed DB claim
        # consumes the external reservation. No actuator may run on failure.
        return self.store.claim(device, nonce, window_seconds=window_seconds)


class SimulationAnchor:
    """In-memory oracle for non-actuating experiments ONLY; not durable."""
    def __init__(self):
        self._claims = set()

    def reserve(self, device: str, nonce_digest: bytes) -> bool:
        key = (device, nonce_digest)
        if key in self._claims:
            return False
        self._claims.add(key)
        return True
