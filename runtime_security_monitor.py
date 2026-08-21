"""Bounded runtime security-event correlation for OmniGuard V2X.

The monitor stores only normalized reason codes, source/category labels, and a
one-way subject token. It intentionally does not retain packet bodies, keys,
tokens, credentials, or arbitrary exception text.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Iterable, List, Optional


RUNTIME_MONITOR_VERSION = "OMNIGUARD_RUNTIME_SECURITY_V1"
SEVERITY_POINTS = {"LOW": 1, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 8}
SAFETY_CRITICAL_CATEGORIES = {
    "LEDGER_INTEGRITY",
    "SERVICE_AUTHENTICITY",
    "TELEMETRY_INTEGRITY",
    "ACTUATOR_INTEGRITY",
}


@dataclass(frozen=True)
class RuntimeSecurityEvent:
    sequence: int
    timestamp: str
    source: str
    category: str
    reason: str
    severity: str
    subject_token: str
    previous_hash: str
    event_hash: str


@dataclass(frozen=True)
class RuntimeSecurityDecision:
    incident_level: str
    recommended_action: str
    score: int
    recent_event_count: int
    recent_sources: tuple[str, ...]
    recent_categories: tuple[str, ...]
    safety_critical: bool

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_code(value: str, fallback: str) -> str:
    text = str(value or "").strip().upper()
    safe = "".join(ch if ch.isalnum() or ch in "_.:-" else "_" for ch in text)
    safe = safe.strip("_")[:128]
    return safe or fallback


def _subject_token(subject: str) -> str:
    raw = str(subject or "").strip()
    if not raw:
        return ""
    return hashlib.sha256(("OMNIGUARD_SUBJECT_V1\0" + raw).encode("utf-8")).hexdigest()[:24]


def classify_security_reason(reason: str) -> tuple[str, str]:
    code = _normalize_code(reason, "UNSPECIFIED_SECURITY_EVENT")

    if "SERVICE_PROOF" in code or "SERVICE_SPOOF" in code:
        return "SERVICE_AUTHENTICITY", "CRITICAL"
    if "TELEMETRY_INTEGRITY" in code or "SENSOR_SPOOF" in code:
        return "TELEMETRY_INTEGRITY", "CRITICAL"
    if "ACTUATOR" in code and ("TAMPER" in code or "UNAUTHORIZED" in code):
        return "ACTUATOR_INTEGRITY", "CRITICAL"
    if (
        code in {
            "CHAIN_COMPROMISED",
            "CHAIN_FAIL",
            "LEDGER_TAMPER",
            "LEDGER_INTEGRITY_FAILURE",
            "BLOCK_SIGNATURE_INVALID",
        }
        or "LEDGER" in code
        or "CHAIN_COMPROM" in code
    ):
        return "LEDGER_INTEGRITY", "CRITICAL"

    if "REPLAY" in code or "NONCE" in code:
        return "REPLAY_DEFENSE", "HIGH"
    if "VOTE" in code or "VALIDATOR" in code or "CONSENSUS" in code:
        return "CONSENSUS_INTEGRITY", "HIGH"
    if "IDENTITY" in code or "UNREGISTERED" in code or "ADMISSION" in code:
        return "IDENTITY_ADMISSION", "HIGH"
    if "AUTH" in code or "MAC" in code or "SIGNATURE" in code:
        return "AUTHENTICATION", "HIGH"
    if "HTTP_401" in code or "HTTP_403" in code:
        return "CONTROL_API_AUTH", "HIGH"
    if "HTTP_409" in code:
        return "CONTROL_API_REPLAY_OR_CONFLICT", "HIGH"
    if "MALFORMED" in code or "INVALID_PAYLOAD" in code or "INVALID_MESSAGE" in code:
        return "MALFORMED_INPUT", "MEDIUM"
    if "STALE" in code or "TIMEOUT" in code or "UNAVAILABLE" in code or "CONNECTION" in code:
        return "AVAILABILITY", "MEDIUM"
    return "SECURITY_POLICY", "MEDIUM"


class RuntimeSecurityMonitor:
    """Correlate normalized security events inside a bounded evidence buffer."""

    def __init__(
        self,
        *,
        capacity: int = 512,
        window_sec: int = 30,
        watch_threshold: int = 4,
        contain_threshold: int = 8,
        critical_threshold: int = 12,
    ):
        self.capacity = min(8192, max(32, int(capacity)))
        self.window_sec = min(3600, max(5, int(window_sec)))
        self.watch_threshold = max(1, int(watch_threshold))
        self.contain_threshold = max(self.watch_threshold, int(contain_threshold))
        self.critical_threshold = max(self.contain_threshold, int(critical_threshold))
        self._lock = threading.RLock()
        self._events: Deque[RuntimeSecurityEvent] = deque()
        self._sequence = 0
        self._anchor_hash = "0" * 64
        self._last_decision = self._decision_for([])

    @staticmethod
    def _event_hash(payload: Dict[str, object]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha3_256(canonical.encode("utf-8")).hexdigest()

    def _recent_events(self, now: Optional[datetime] = None) -> List[RuntimeSecurityEvent]:
        current = now or _utc_now()
        cutoff = current - timedelta(seconds=self.window_sec)
        recent: List[RuntimeSecurityEvent] = []
        for event in self._events:
            try:
                ts = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    recent.append(event)
            except Exception:
                continue
        return recent

    def _decision_for(self, events: Iterable[RuntimeSecurityEvent]) -> RuntimeSecurityDecision:
        recent = list(events)
        score = sum(SEVERITY_POINTS.get(event.severity, 2) for event in recent)
        sources = tuple(sorted({event.source for event in recent}))
        categories = tuple(sorted({event.category for event in recent}))
        safety_critical = any(event.category in SAFETY_CRITICAL_CATEGORIES for event in recent)
        has_critical = any(event.severity == "CRITICAL" for event in recent)

        if (has_critical or score >= self.critical_threshold) and safety_critical:
            level = "CRITICAL"
            action = "SAFE_MODE_REQUEST"
        elif score >= self.contain_threshold or has_critical:
            level = "CONTAIN"
            action = "ISOLATE_NETWORK"
        elif score >= self.watch_threshold:
            level = "WATCH"
            action = "AUDIT_ONLY"
        else:
            level = "NORMAL"
            action = "NONE"

        return RuntimeSecurityDecision(
            incident_level=level,
            recommended_action=action,
            score=score,
            recent_event_count=len(recent),
            recent_sources=sources,
            recent_categories=categories,
            safety_critical=safety_critical,
        )

    def observe(
        self,
        source: str,
        reason: str,
        *,
        subject: str = "",
        category: str = "",
        severity: str = "",
        timestamp: Optional[datetime] = None,
    ) -> RuntimeSecurityDecision:
        event_time = timestamp or _utc_now()
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        event_time = event_time.astimezone(timezone.utc)
        normalized_reason = _normalize_code(reason, "UNSPECIFIED_SECURITY_EVENT")
        classified_category, classified_severity = classify_security_reason(normalized_reason)
        event_category = _normalize_code(category, classified_category) if category else classified_category
        event_severity = _normalize_code(severity, classified_severity) if severity else classified_severity
        if event_severity not in SEVERITY_POINTS:
            event_severity = classified_severity

        with self._lock:
            if len(self._events) >= self.capacity:
                removed = self._events.popleft()
                self._anchor_hash = removed.event_hash

            self._sequence += 1
            previous_hash = self._events[-1].event_hash if self._events else self._anchor_hash
            unsigned = {
                "sequence": self._sequence,
                "timestamp": event_time.isoformat(),
                "source": _normalize_code(source, "UNKNOWN_SOURCE"),
                "category": event_category,
                "reason": normalized_reason,
                "severity": event_severity,
                "subject_token": _subject_token(subject),
                "previous_hash": previous_hash,
            }
            event = RuntimeSecurityEvent(event_hash=self._event_hash(unsigned), **unsigned)
            self._events.append(event)
            self._last_decision = self._decision_for(self._recent_events(event_time))
            return self._last_decision

    def verify_evidence_chain(self) -> bool:
        with self._lock:
            expected_previous = self._anchor_hash
            for event in self._events:
                if event.previous_hash != expected_previous:
                    return False
                unsigned = asdict(event)
                received = unsigned.pop("event_hash")
                if received != self._event_hash(unsigned):
                    return False
                expected_previous = event.event_hash
            return True

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {
                "version": RUNTIME_MONITOR_VERSION,
                "capacity": self.capacity,
                "window_sec": self.window_sec,
                "retained_events": len(self._events),
                "anchor_hash": self._anchor_hash,
                "evidence_chain_valid": self.verify_evidence_chain(),
                "last_decision": self._last_decision.to_dict(),
                "events": [asdict(event) for event in self._events],
                "raw_payloads_stored": False,
                "secret_values_stored": False,
                "raw_subjects_stored": False,
            }

    def metadata(self) -> Dict[str, object]:
        snap = self.snapshot()
        return {
            "version": snap["version"],
            "capacity": snap["capacity"],
            "window_sec": snap["window_sec"],
            "retained_events": snap["retained_events"],
            "evidence_chain_valid": snap["evidence_chain_valid"],
            "last_decision": snap["last_decision"],
            "raw_payloads_stored": False,
            "secret_values_stored": False,
            "raw_subjects_stored": False,
        }

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._sequence = 0
            self._anchor_hash = "0" * 64
            self._last_decision = self._decision_for([])


_GLOBAL_MONITOR = RuntimeSecurityMonitor()


def get_runtime_security_monitor() -> RuntimeSecurityMonitor:
    return _GLOBAL_MONITOR


def reset_runtime_security_monitor() -> RuntimeSecurityMonitor:
    _GLOBAL_MONITOR.reset()
    return _GLOBAL_MONITOR
