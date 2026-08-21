"""Tamper-evident incident response and explicit recovery gates for OmniGuard V2X.

The module consumes the normalized, value-free runtime security monitor output.
It intentionally does not actuate CAN, serial, brakes, throttle, ignition, or
network interfaces.  It persists only normalized incident state and evidence
hashes in an append-mode HMAC-authenticated JSONL journal.

Local journal protection is tamper-evident, not tamper-proof: an attacker with
both filesystem-write access and the journal signing key remains outside this
module's protection boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

from key_provider import KeyProvider
from replay_security import BoundedReplayCache
from runtime_security_monitor import RuntimeSecurityMonitor


INCIDENT_RESPONSE_VERSION = "OMNIGUARD_INCIDENT_RESPONSE_V1"
INCIDENT_EVIDENCE_VERSION = "OMNIGUARD_INCIDENT_EVIDENCE_V1"
INCIDENT_OPERATOR_AUTH_VERSION = "OMNIGUARD_INCIDENT_OPERATOR_AUTH_V1"

_EVIDENCE_DOMAIN = (INCIDENT_EVIDENCE_VERSION + "\0").encode("utf-8")
_OPERATOR_DOMAIN = (INCIDENT_OPERATOR_AUTH_VERSION + "\0").encode("utf-8")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_ALLOWED_ACTIONS = {"ACKNOWLEDGE", "RECOVER"}
_STATE_ORDER = {
    "CLEAR": 0,
    "OPEN": 1,
    "ACKNOWLEDGED": 2,
    "RECOVERY_PENDING": 3,
    "RECOVERED": 4,
}
_ACTION_ORDER = {
    "NONE": 0,
    "AUDIT_ONLY": 1,
    "ISOLATE_NETWORK": 2,
    "SAFE_MODE_REQUEST": 3,
}


class IncidentResponseError(RuntimeError):
    """Fail-closed incident response error with a stable reason code."""

    def __init__(self, reason: str):
        self.reason = str(reason)
        super().__init__(self.reason)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_code(value: str, fallback: str) -> str:
    text = str(value or "").strip().upper()
    safe = "".join(ch if ch.isalnum() or ch in "_.:-" else "_" for ch in text)
    safe = safe.strip("_")[:128]
    return safe or fallback


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _parse_utc(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _safe_evidence_filename(filename: str) -> str:
    name = str(filename or "incident-evidence.jsonl").strip()
    if not name or name in {".", ".."} or Path(name).name != name:
        raise IncidentResponseError("INVALID_EVIDENCE_FILENAME")
    if not name.endswith(".jsonl"):
        raise IncidentResponseError("INVALID_EVIDENCE_FILENAME")
    return name


def _valid_hex(value: str, bytes_min: int, bytes_max: int) -> bool:
    text = str(value or "")
    if len(text) % 2 != 0 or not _HEX_RE.fullmatch(text):
        return False
    size = len(text) // 2
    return bytes_min <= size <= bytes_max


def _monitor_tail_hash(snapshot: Mapping[str, object]) -> str:
    events = snapshot.get("events")
    if isinstance(events, list) and events:
        last = events[-1]
        if isinstance(last, Mapping):
            value = str(last.get("event_hash", ""))
            if len(value) == 64 and _HEX_RE.fullmatch(value):
                return value.lower()
    anchor = str(snapshot.get("anchor_hash", ""))
    if len(anchor) == 64 and _HEX_RE.fullmatch(anchor):
        return anchor.lower()
    return "0" * 64


@dataclass
class IncidentStatus:
    incident_id: str = ""
    state: str = "CLEAR"
    strongest_action: str = "NONE"
    highest_incident_level: str = "NORMAL"
    safety_critical: bool = False
    opened_at: str = ""
    acknowledged_at: str = ""
    recovered_at: str = ""
    healthy_observations: int = 0
    required_healthy_observations: int = 3
    last_monitor_event_count: int = 0
    last_monitor_tail_hash: str = "0" * 64
    last_monitor_chain_valid: bool = True

    @property
    def active(self) -> bool:
        return bool(self.incident_id) and self.state != "RECOVERED"

    def to_dict(self) -> Dict[str, object]:
        payload = asdict(self)
        payload["active"] = self.active
        return payload


class IncidentEvidenceJournal:
    """Append-mode, hash-chained, HMAC-authenticated incident evidence journal."""

    def __init__(
        self,
        directory: str,
        provider: KeyProvider,
        *,
        key_name: str = "SMARTCAR_INCIDENT_EVIDENCE_KEY",
        filename: str = "incident-evidence.jsonl",
        max_file_bytes: int = 64 * 1024 * 1024,
        max_record_bytes: int = 16 * 1024,
    ):
        self.provider = provider
        self.key_name = str(key_name)
        self.max_file_bytes = min(1024 * 1024 * 1024, max(64 * 1024, int(max_file_bytes)))
        self.max_record_bytes = min(256 * 1024, max(1024, int(max_record_bytes)))
        self._lock = threading.RLock()

        base = Path(str(directory or "logs/security")).expanduser()
        if base.exists() and base.is_symlink():
            raise IncidentResponseError("EVIDENCE_DIRECTORY_SYMLINK_REJECTED")
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(base, 0o700)
        except OSError:
            pass
        self.directory = base.resolve()
        self.path = self.directory / _safe_evidence_filename(filename)
        if self.path.exists() and self.path.is_symlink():
            raise IncidentResponseError("EVIDENCE_JOURNAL_SYMLINK_REJECTED")

        self._entries: List[Dict[str, object]] = []
        self._tail_hash = "0" * 64
        self._sequence = 0
        self._load_and_verify()

    @staticmethod
    def _entry_hash(unsigned: Mapping[str, object]) -> str:
        return hashlib.sha3_256(_canonical_bytes(unsigned)).hexdigest()

    def _signature(self, unsigned: Mapping[str, object], entry_hash: str, purpose: str) -> str:
        signed = {
            "entry": dict(unsigned),
            "entry_hash": str(entry_hash).lower(),
        }
        return self.provider.hmac_sha256(
            self.key_name,
            _EVIDENCE_DOMAIN + _canonical_bytes(signed),
            purpose=purpose,
        )

    def _verify_entry(self, entry: Mapping[str, object], expected_sequence: int, expected_previous: str) -> bool:
        try:
            received_hash = str(entry.get("entry_hash", "")).lower()
            received_signature = str(entry.get("signature", "")).lower()
            if len(received_hash) != 64 or not _HEX_RE.fullmatch(received_hash):
                return False
            if len(received_signature) != 64 or not _HEX_RE.fullmatch(received_signature):
                return False
            unsigned = dict(entry)
            unsigned.pop("entry_hash", None)
            unsigned.pop("signature", None)
            if str(unsigned.get("version", "")) != INCIDENT_EVIDENCE_VERSION:
                return False
            if int(unsigned.get("sequence", -1)) != expected_sequence:
                return False
            if str(unsigned.get("previous_entry_hash", "")).lower() != expected_previous:
                return False
            if self._entry_hash(unsigned) != received_hash:
                return False
            expected_signature = self._signature(unsigned, received_hash, "incident-evidence-verify")
            return hmac.compare_digest(received_signature, expected_signature.lower())
        except Exception:
            return False

    def _load_and_verify(self) -> None:
        with self._lock:
            if not self.path.exists():
                return
            try:
                size = self.path.stat().st_size
            except OSError as exc:
                raise IncidentResponseError("EVIDENCE_JOURNAL_STAT_FAILED") from exc
            if size > self.max_file_bytes:
                raise IncidentResponseError("EVIDENCE_JOURNAL_CAPACITY_EXCEEDED")

            entries: List[Dict[str, object]] = []
            expected_previous = "0" * 64
            expected_sequence = 1
            try:
                with self.path.open("rb") as handle:
                    for raw_line in handle:
                        if len(raw_line) > self.max_record_bytes:
                            raise IncidentResponseError("EVIDENCE_RECORD_TOO_LARGE")
                        if not raw_line.strip():
                            continue
                        try:
                            entry = json.loads(raw_line.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                            raise IncidentResponseError("EVIDENCE_JOURNAL_MALFORMED") from exc
                        if not isinstance(entry, dict):
                            raise IncidentResponseError("EVIDENCE_JOURNAL_MALFORMED")
                        if not self._verify_entry(entry, expected_sequence, expected_previous):
                            raise IncidentResponseError("EVIDENCE_JOURNAL_INVALID")
                        entries.append(dict(entry))
                        expected_previous = str(entry["entry_hash"]).lower()
                        expected_sequence += 1
            except IncidentResponseError:
                raise
            except OSError as exc:
                raise IncidentResponseError("EVIDENCE_JOURNAL_READ_FAILED") from exc

            self._entries = entries
            self._sequence = len(entries)
            self._tail_hash = expected_previous

    def verify(self) -> bool:
        with self._lock:
            expected_previous = "0" * 64
            for expected_sequence, entry in enumerate(self._entries, start=1):
                if not self._verify_entry(entry, expected_sequence, expected_previous):
                    return False
                expected_previous = str(entry["entry_hash"]).lower()
            return expected_previous == self._tail_hash

    def _append_bytes(self, payload: bytes) -> None:
        if len(payload) > self.max_record_bytes:
            raise IncidentResponseError("EVIDENCE_RECORD_TOO_LARGE")
        current_size = self.path.stat().st_size if self.path.exists() else 0
        if current_size + len(payload) > self.max_file_bytes:
            raise IncidentResponseError("EVIDENCE_JOURNAL_CAPACITY_EXCEEDED")
        if self.path.exists() and self.path.is_symlink():
            raise IncidentResponseError("EVIDENCE_JOURNAL_SYMLINK_REJECTED")

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= int(getattr(os, "O_NOFOLLOW"))
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise IncidentResponseError("EVIDENCE_JOURNAL_OPEN_FAILED") from exc
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise IncidentResponseError("EVIDENCE_JOURNAL_WRITE_FAILED")
                view = view[written:]
            os.fsync(fd)
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
        finally:
            os.close(fd)

    def append_transition(
        self,
        record_type: str,
        status: IncidentStatus,
        monitor_snapshot: Mapping[str, object],
    ) -> Dict[str, object]:
        with self._lock:
            if not self.verify():
                raise IncidentResponseError("EVIDENCE_JOURNAL_INVALID")
            decision = monitor_snapshot.get("last_decision")
            if not isinstance(decision, Mapping):
                decision = {}
            unsigned: Dict[str, object] = {
                "version": INCIDENT_EVIDENCE_VERSION,
                "sequence": self._sequence + 1,
                "timestamp": _utc_now().isoformat(),
                "record_type": _normalize_code(record_type, "INCIDENT_TRANSITION"),
                "incident_id": status.incident_id,
                "incident_state": status.state,
                "strongest_action": status.strongest_action,
                "highest_incident_level": status.highest_incident_level,
                "safety_critical": bool(status.safety_critical),
                "healthy_observations": int(status.healthy_observations),
                "required_healthy_observations": int(status.required_healthy_observations),
                "monitor_event_count": int(monitor_snapshot.get("retained_events", 0)),
                "monitor_chain_valid": bool(monitor_snapshot.get("evidence_chain_valid", False)),
                "monitor_tail_hash": _monitor_tail_hash(monitor_snapshot),
                "decision_score": int(decision.get("score", 0)),
                "decision_action": _normalize_code(str(decision.get("recommended_action", "NONE")), "NONE"),
                "decision_level": _normalize_code(str(decision.get("incident_level", "NORMAL")), "NORMAL"),
                "recent_sources": sorted(_normalize_code(str(v), "UNKNOWN_SOURCE") for v in decision.get("recent_sources", []) if str(v)),
                "recent_categories": sorted(_normalize_code(str(v), "SECURITY_POLICY") for v in decision.get("recent_categories", []) if str(v)),
                "previous_entry_hash": self._tail_hash,
            }
            entry_hash = self._entry_hash(unsigned)
            signature = self._signature(unsigned, entry_hash, "incident-evidence-append")
            entry = dict(unsigned)
            entry["entry_hash"] = entry_hash
            entry["signature"] = signature
            line = _canonical_bytes(entry) + b"\n"
            self._append_bytes(line)
            self._entries.append(entry)
            self._sequence += 1
            self._tail_hash = entry_hash
            return dict(entry)

    def entries(self) -> List[Dict[str, object]]:
        with self._lock:
            return [dict(entry) for entry in self._entries]

    def metadata(self) -> Dict[str, object]:
        with self._lock:
            return {
                "version": INCIDENT_EVIDENCE_VERSION,
                "entry_count": len(self._entries),
                "tail_hash": self._tail_hash,
                "journal_valid": self.verify(),
                "max_file_bytes": self.max_file_bytes,
                "max_record_bytes": self.max_record_bytes,
                "append_mode": True,
                "fsync_each_entry": True,
                "secret_values_stored": False,
                "raw_payloads_stored": False,
                "raw_subjects_stored": False,
                "tamper_proof_storage_claim": False,
            }



def _operator_message(action: str, incident_id: str, timestamp: str, nonce: str) -> bytes:
    payload = {
        "version": INCIDENT_OPERATOR_AUTH_VERSION,
        "action": _normalize_code(action, "INVALID"),
        "incident_id": str(incident_id),
        "timestamp": str(timestamp),
        "nonce": str(nonce).lower(),
    }
    return _OPERATOR_DOMAIN + _canonical_bytes(payload)


def build_operator_authorization(
    provider: KeyProvider,
    action: str,
    incident_id: str,
    *,
    key_name: str = "SMARTCAR_INCIDENT_OPERATOR_KEY",
    timestamp: Optional[datetime] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    action_code = _normalize_code(action, "INVALID")
    if action_code not in _ALLOWED_ACTIONS:
        raise IncidentResponseError("INVALID_OPERATOR_ACTION")
    if not str(incident_id or "").strip():
        raise IncidentResponseError("INCIDENT_ID_REQUIRED")
    ts = timestamp or _utc_now()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ts_text = ts.astimezone(timezone.utc).isoformat()
    nonce_text = str(nonce or secrets.token_hex(16)).lower()
    if not _valid_hex(nonce_text, 16, 64):
        raise IncidentResponseError("INVALID_OPERATOR_NONCE")
    signature = provider.hmac_sha256(
        key_name,
        _operator_message(action_code, incident_id, ts_text, nonce_text),
        purpose="incident-operator-sign",
    )
    return {
        "version": INCIDENT_OPERATOR_AUTH_VERSION,
        "action": action_code,
        "incident_id": str(incident_id),
        "timestamp": ts_text,
        "nonce": nonce_text,
        "signature": signature,
    }


class IncidentResponseManager:
    """Explicit acknowledgement and recovery gate over a runtime monitor."""

    def __init__(
        self,
        monitor: RuntimeSecurityMonitor,
        journal: IncidentEvidenceJournal,
        operator_provider: KeyProvider,
        *,
        operator_key_name: str = "SMARTCAR_INCIDENT_OPERATOR_KEY",
        auth_window_sec: int = 120,
        operator_nonce_cache_entries: int = 1024,
        required_healthy_observations: int = 3,
    ):
        self.monitor = monitor
        self.journal = journal
        self.operator_provider = operator_provider
        self.operator_key_name = str(operator_key_name)
        self.auth_window_sec = min(900, max(15, int(auth_window_sec)))
        self.required_healthy_observations = min(100, max(2, int(required_healthy_observations)))
        self._operator_nonces = BoundedReplayCache(max_entries=max(16, int(operator_nonce_cache_entries)))
        self._lock = threading.RLock()
        self.status = IncidentStatus(required_healthy_observations=self.required_healthy_observations)
        self._restore_from_journal()

    def _restore_from_journal(self) -> None:
        entries = self.journal.entries()
        if not entries:
            return
        last = entries[-1]
        state = str(last.get("incident_state", "CLEAR"))
        if state not in _STATE_ORDER:
            raise IncidentResponseError("EVIDENCE_JOURNAL_STATE_INVALID")
        self.status = IncidentStatus(
            incident_id=str(last.get("incident_id", "")),
            state=state,
            strongest_action=str(last.get("strongest_action", "NONE")),
            highest_incident_level=str(last.get("highest_incident_level", "NORMAL")),
            safety_critical=bool(last.get("safety_critical", False)),
            healthy_observations=int(last.get("healthy_observations", 0)),
            required_healthy_observations=int(last.get("required_healthy_observations", self.required_healthy_observations)),
            last_monitor_event_count=int(last.get("monitor_event_count", 0)),
            last_monitor_tail_hash=str(last.get("monitor_tail_hash", "0" * 64)),
            last_monitor_chain_valid=bool(last.get("monitor_chain_valid", False)),
        )
        # Timestamps are intentionally state-transition timestamps.  They are
        # not security decisions and are safe to reconstruct approximately.
        if self.status.state != "CLEAR":
            self.status.opened_at = str(last.get("timestamp", ""))

    @staticmethod
    def _stronger_action(current: str, candidate: str) -> str:
        return candidate if _ACTION_ORDER.get(candidate, -1) > _ACTION_ORDER.get(current, -1) else current

    @staticmethod
    def _higher_level(current: str, candidate: str) -> str:
        order = {"NORMAL": 0, "WATCH": 1, "CONTAIN": 2, "CRITICAL": 3}
        return candidate if order.get(candidate, -1) > order.get(current, -1) else current

    def _new_incident(self, snapshot: Mapping[str, object], decision: Mapping[str, object]) -> None:
        now = _utc_now().isoformat()
        action = str(decision.get("recommended_action", "NONE"))
        level = str(decision.get("incident_level", "NORMAL"))
        self.status = IncidentStatus(
            incident_id="inc-" + secrets.token_hex(12),
            state="OPEN",
            strongest_action=action,
            highest_incident_level=level,
            safety_critical=bool(decision.get("safety_critical", False) or action == "SAFE_MODE_REQUEST"),
            opened_at=now,
            healthy_observations=0,
            required_healthy_observations=self.required_healthy_observations,
            last_monitor_event_count=int(snapshot.get("retained_events", 0)),
            last_monitor_tail_hash=_monitor_tail_hash(snapshot),
            last_monitor_chain_valid=bool(snapshot.get("evidence_chain_valid", False)),
        )
        self.journal.append_transition("INCIDENT_OPENED", self.status, snapshot)

    def _record_update(self, record_type: str, snapshot: Mapping[str, object]) -> None:
        self.status.last_monitor_event_count = int(snapshot.get("retained_events", 0))
        self.status.last_monitor_tail_hash = _monitor_tail_hash(snapshot)
        self.status.last_monitor_chain_valid = bool(snapshot.get("evidence_chain_valid", False))
        self.journal.append_transition(record_type, self.status, snapshot)

    def evaluate(self) -> Dict[str, object]:
        """Evaluate the current monitor state and advance only safe transitions."""
        with self._lock:
            snapshot = self.monitor.snapshot()
            decision = snapshot.get("last_decision")
            if not isinstance(decision, Mapping):
                raise IncidentResponseError("RUNTIME_DECISION_MISSING")

            if not bool(snapshot.get("evidence_chain_valid", False)):
                decision = {
                    "incident_level": "CRITICAL",
                    "recommended_action": "SAFE_MODE_REQUEST",
                    "score": max(12, int(decision.get("score", 0))),
                    "recent_event_count": int(snapshot.get("retained_events", 0)),
                    "recent_sources": ["RUNTIME_MONITOR"],
                    "recent_categories": ["RUNTIME_EVIDENCE_INTEGRITY"],
                    "safety_critical": True,
                }

            action = str(decision.get("recommended_action", "NONE"))
            level = str(decision.get("incident_level", "NORMAL"))
            event_count = int(snapshot.get("retained_events", 0))
            tail_hash = _monitor_tail_hash(snapshot)

            if action in {"ISOLATE_NETWORK", "SAFE_MODE_REQUEST"} or level in {"CONTAIN", "CRITICAL"}:
                if not self.status.incident_id or self.status.state == "RECOVERED":
                    self._new_incident(snapshot, decision)
                else:
                    changed = (
                        event_count != self.status.last_monitor_event_count
                        or tail_hash != self.status.last_monitor_tail_hash
                        or _ACTION_ORDER.get(action, 0) > _ACTION_ORDER.get(self.status.strongest_action, 0)
                    )
                    self.status.strongest_action = self._stronger_action(self.status.strongest_action, action)
                    self.status.highest_incident_level = self._higher_level(self.status.highest_incident_level, level)
                    self.status.safety_critical = bool(
                        self.status.safety_critical
                        or decision.get("safety_critical", False)
                        or action == "SAFE_MODE_REQUEST"
                    )
                    self.status.healthy_observations = 0
                    if changed:
                        # Any new containment evidence invalidates a prior acknowledgement.
                        self.status.state = "OPEN"
                        self.status.acknowledged_at = ""
                        self._record_update("INCIDENT_UPDATED", snapshot)
            elif level == "NORMAL" and action == "NONE" and self.status.active:
                if self.status.state in {"ACKNOWLEDGED", "RECOVERY_PENDING"}:
                    first_pending = self.status.state != "RECOVERY_PENDING"
                    self.status.state = "RECOVERY_PENDING"
                    self.status.healthy_observations = min(
                        self.required_healthy_observations,
                        self.status.healthy_observations + 1,
                    )
                    self._record_update(
                        "RECOVERY_WINDOW_STARTED" if first_pending else "RECOVERY_HEALTHY_OBSERVED",
                        snapshot,
                    )
                else:
                    # Healthy time alone never acknowledges an incident.
                    self.status.healthy_observations = 0
                    self.status.last_monitor_event_count = event_count
                    self.status.last_monitor_tail_hash = tail_hash
                    self.status.last_monitor_chain_valid = bool(snapshot.get("evidence_chain_valid", False))
            elif self.status.active:
                # WATCH/AUDIT_ONLY is not healthy enough for recovery.
                self.status.healthy_observations = 0
                if self.status.state == "RECOVERY_PENDING":
                    self.status.state = "ACKNOWLEDGED"
                    self._record_update("RECOVERY_WINDOW_RESET", snapshot)

            return self.metadata()

    def _prune_operator_nonces(self, now_mono: float) -> None:
        stale = [nonce for nonce, expiry in dict.items(self._operator_nonces) if float(expiry) <= now_mono]
        for nonce in stale:
            dict.pop(self._operator_nonces, nonce, None)

    def _verify_operator_authorization(self, authorization: Mapping[str, str], expected_action: str) -> None:
        if not isinstance(authorization, Mapping):
            raise IncidentResponseError("OPERATOR_AUTH_REQUIRED")
        if str(authorization.get("version", "")) != INCIDENT_OPERATOR_AUTH_VERSION:
            raise IncidentResponseError("OPERATOR_AUTH_VERSION_INVALID")
        action = _normalize_code(str(authorization.get("action", "")), "INVALID")
        if action != expected_action:
            raise IncidentResponseError("OPERATOR_ACTION_MISMATCH")
        if str(authorization.get("incident_id", "")) != self.status.incident_id:
            raise IncidentResponseError("OPERATOR_INCIDENT_MISMATCH")
        timestamp = str(authorization.get("timestamp", ""))
        parsed = _parse_utc(timestamp)
        if parsed is None:
            raise IncidentResponseError("OPERATOR_TIMESTAMP_INVALID")
        skew = abs((_utc_now() - parsed).total_seconds())
        if skew > self.auth_window_sec:
            raise IncidentResponseError("OPERATOR_AUTH_STALE")
        nonce = str(authorization.get("nonce", "")).lower()
        if not _valid_hex(nonce, 16, 64):
            raise IncidentResponseError("INVALID_OPERATOR_NONCE")
        signature = str(authorization.get("signature", "")).lower()
        if len(signature) != 64 or not _HEX_RE.fullmatch(signature):
            raise IncidentResponseError("OPERATOR_SIGNATURE_INVALID")

        expected = self.operator_provider.hmac_sha256(
            self.operator_key_name,
            _operator_message(action, self.status.incident_id, timestamp, nonce),
            purpose="incident-operator-verify",
        )
        if not hmac.compare_digest(signature, expected.lower()):
            raise IncidentResponseError("OPERATOR_SIGNATURE_INVALID")

        now_mono = time.monotonic()
        self._prune_operator_nonces(now_mono)
        if nonce in self._operator_nonces:
            raise IncidentResponseError("OPERATOR_AUTH_REPLAY")
        self._operator_nonces[nonce] = now_mono + self.auth_window_sec

    def acknowledge(self, authorization: Mapping[str, str]) -> Dict[str, object]:
        with self._lock:
            if not self.status.active:
                raise IncidentResponseError("NO_ACTIVE_INCIDENT")
            self._verify_operator_authorization(authorization, "ACKNOWLEDGE")
            if self.status.state not in {"OPEN", "ACKNOWLEDGED"}:
                raise IncidentResponseError("INCIDENT_NOT_ACKNOWLEDGEABLE")
            if self.status.state == "OPEN":
                self.status.state = "ACKNOWLEDGED"
                self.status.acknowledged_at = _utc_now().isoformat()
                self.status.healthy_observations = 0
                self._record_update("INCIDENT_ACKNOWLEDGED", self.monitor.snapshot())
            return self.metadata()

    def recovery_gate(self) -> Dict[str, object]:
        snapshot = self.monitor.snapshot()
        decision = snapshot.get("last_decision") if isinstance(snapshot.get("last_decision"), Mapping) else {}
        normal = (
            bool(snapshot.get("evidence_chain_valid", False))
            and str(decision.get("incident_level", "")) == "NORMAL"
            and str(decision.get("recommended_action", "")) == "NONE"
        )
        return {
            "incident_id": self.status.incident_id,
            "state": self.status.state,
            "monitor_normal": normal,
            "monitor_chain_valid": bool(snapshot.get("evidence_chain_valid", False)),
            "healthy_observations": self.status.healthy_observations,
            "required_healthy_observations": self.required_healthy_observations,
            "healthy_window_satisfied": self.status.healthy_observations >= self.required_healthy_observations,
            "safety_interlock_confirmation_required": bool(self.status.safety_critical),
            "operator_recovery_authorization_required": True,
            "automatic_recovery_allowed": False,
        }

    def recover(
        self,
        authorization: Mapping[str, str],
        *,
        safety_interlock_confirmed: bool = False,
    ) -> Dict[str, object]:
        with self._lock:
            if not self.status.active:
                raise IncidentResponseError("NO_ACTIVE_INCIDENT")
            self._verify_operator_authorization(authorization, "RECOVER")
            gate = self.recovery_gate()
            if self.status.state != "RECOVERY_PENDING":
                raise IncidentResponseError("RECOVERY_STATE_NOT_READY")
            if not bool(gate["monitor_normal"]):
                raise IncidentResponseError("RUNTIME_MONITOR_NOT_HEALTHY")
            if not bool(gate["healthy_window_satisfied"]):
                raise IncidentResponseError("RECOVERY_HEALTH_WINDOW_INCOMPLETE")
            if self.status.safety_critical and not bool(safety_interlock_confirmed):
                raise IncidentResponseError("SAFETY_INTERLOCK_CONFIRMATION_REQUIRED")

            self.status.state = "RECOVERED"
            self.status.recovered_at = _utc_now().isoformat()
            self._record_update("INCIDENT_RECOVERED", self.monitor.snapshot())
            return self.metadata()

    def metadata(self) -> Dict[str, object]:
        return {
            "version": INCIDENT_RESPONSE_VERSION,
            "status": self.status.to_dict(),
            "recovery_gate": self.recovery_gate(),
            "journal": self.journal.metadata(),
            "operator_auth_window_sec": self.auth_window_sec,
            "operator_nonce_cache": self._operator_nonces.metadata(),
            "automatic_recovery_allowed": False,
            "hardware_actuation_performed": False,
            "secret_values_exposed": False,
            "raw_payloads_exposed": False,
            "raw_subjects_exposed": False,
        }
