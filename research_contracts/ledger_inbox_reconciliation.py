"""Non-actuating ledger reconciliation contract for a durable V2X event inbox.

A remote ledger MUST implement an atomic, durable append_once(event_id, digest)
and a verified lookup(event_id). This adapter does not claim consensus finality.
UNKNOWN lookup must fail closed; ABSENT alone never authorizes a non-idempotent
append. Call only after authenticating the sender and validating the envelope.
"""
import hashlib
import json


class ReconciliationUnavailable(RuntimeError):
    pass


class LedgerIdentityConflict(ValueError):
    pass


def event_id(device_id, nonce):
    """Domain-separated canonical event identity; never includes mutable payload."""
    if not isinstance(device_id, str) or not device_id or len(device_id) > 96:
        raise ValueError("invalid device_id")
    if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
        raise ValueError("invalid nonce")
    encoded = json.dumps([device_id, nonce], ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"omniguard-v2x-event-v1\\0" + encoded).hexdigest()


class LedgerReconciler:
    """Adapter for a *verified*, atomic-idempotent ledger interface.

    lookup(event_id) -> None if definitely absent, (digest, reference) if
    verified included, or raises when inclusion cannot be determined.
    append_once(event_id, digest) -> reference; atomic deduplication MUST
    be enforced by the ledger, not by this caller.
    """

    def __init__(self, inbox, ledger):
        self.inbox = inbox
        self.ledger = ledger

    def reconcile(self, device_id, nonce, payload, *, after_append=None):
        state = self.inbox.admit(device_id, nonce, payload)
        digest = self.inbox.digest(payload)
        identity = event_id(device_id, nonce)
        try:
            inclusion = self.ledger.lookup(identity)
        except Exception as exc:
            raise ReconciliationUnavailable("verified ledger lookup unavailable") from exc
        if inclusion is not None:
            found_digest, reference = inclusion
            if found_digest != digest:
                raise LedgerIdentityConflict("ledger event identity has conflicting digest")
            if not isinstance(reference, str) or not reference:
                raise ReconciliationUnavailable("invalid verified ledger reference")
            self.inbox.mark_committed(device_id, nonce, reference)
            return "RECOVERED" if state != "COMMITTED" else "COMMITTED"
        if state == "COMMITTED":
            raise ReconciliationUnavailable("inbox committed but verified inclusion missing")
        if not getattr(self.ledger, "atomic_append_once", False):
            raise ReconciliationUnavailable("ledger lacks atomic idempotent append contract")
        try:
            reference = self.ledger.append_once(identity, digest)
        except Exception as exc:
            raise ReconciliationUnavailable("append outcome unknown; reconcile before retry") from exc
        if after_append is not None:
            after_append()  # deterministic crash boundary, before inbox COMMITTED
        # Never trust the append return alone: verify the durable inclusion.
        try:
            inclusion = self.ledger.lookup(identity)
        except Exception as exc:
            raise ReconciliationUnavailable("post-append verification unavailable") from exc
        if inclusion != (digest, reference):
            raise ReconciliationUnavailable("post-append inclusion mismatch or missing")
        self.inbox.mark_committed(device_id, nonce, reference)
        return "APPENDED"
