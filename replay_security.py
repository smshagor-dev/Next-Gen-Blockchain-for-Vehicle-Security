"""Fail-closed bounded replay-cache primitives for OmniGuard protocols."""

from __future__ import annotations

from typing import Any


class BoundedReplayCache(dict):
    """Dictionary-compatible replay cache with fail-closed saturation.

    Existing protocol helpers test ``nonce in cache`` before inserting. When
    this cache is at capacity, an unknown nonce deliberately reports as present,
    causing the protocol to reject it instead of growing memory without bound or
    evicting a still-live nonce that could then be replayed.
    """

    def __init__(self, *args: Any, max_entries: int = 4096, **kwargs: Any):
        self.max_entries = max(16, int(max_entries))
        self.saturation_rejections = 0
        super().__init__(*args, **kwargs)
        if len(self) > self.max_entries:
            raise ValueError("initial replay cache exceeds configured capacity")

    def __contains__(self, key: object) -> bool:
        if dict.__contains__(self, key):
            return True
        if len(self) >= self.max_entries:
            self.saturation_rejections += 1
            return True
        return False

    def metadata(self) -> dict:
        return {
            "policy": "OMNIGUARD_BOUNDED_REPLAY_CACHE_V1",
            "entries": len(self),
            "max_entries": self.max_entries,
            "saturation_rejections": self.saturation_rejections,
            "evicts_live_nonces": False,
            "fail_closed_on_saturation": True,
        }
