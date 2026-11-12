"""Evidence-gated network event admission for the authenticated V2X hub.

Research prototype: no cryptographic primitive, Sybil resistance, proof of
physical sensor origin, or vehicle actuation authority is provided.

The calling hub MUST verify the signed sender/session and replay nonce before
calling evaluate(). The gate decides whether to *relay a network assertion*;
it never controls ECU, CAN, braking, or local emergency safety functions.
"""
from __future__ import annotations

import math
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, FrozenSet

EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
EVENT_CLASSES: FrozenSet[str] = frozenset(
    {"COLLISION", "OBSTACLE", "ROAD_HAZARD", "TRAFFIC_CONTROL"}
)
MAX_EVENT_AGE_SECONDS = 15
EARTH_RADIUS_M = 6371000.0


@dataclass(frozen=True)
class AdmissionDecision:
    status: str
    reason: str
    relayed: bool
    independent_sources: int = 0
    incident_id: str = ""


@dataclass(frozen=True)
class Evidence:
    incident_id: str
    event_class: str
    observed_at: datetime
    lat: float
    lon: float
    sensor_sha256: str


@dataclass
class IncidentState:
    observed_at: datetime
    lat: float
    lon: float
    event_class: str
    created_monotonic: float
    reports: Dict[str, str] = field(default_factory=dict)
    accepted: bool = False


def _numeric(value: object, name: str, low: float, high: float) -> float:
    # bool is an int in Python, but is not an acceptable coordinate.
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError(name + "_INVALID")
    number = float(value)
    if not math.isfinite(number) or not low <= number <= high:
        raise ValueError(name + "_INVALID")
    return number


def _utc_time(raw: object) -> datetime:
    if not isinstance(raw, str):
        raise ValueError("OBSERVED_AT_INVALID")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("OBSERVED_AT_INVALID") from exc
    if parsed.tzinfo is None:
        raise ValueError("OBSERVED_AT_MISSING_TIMEZONE")
    return parsed.astimezone(timezone.utc)


def _haversine_m(lat_a: float, lon_a: float, lat_b: float, lon_b: float) -> float:
    p1, p2 = math.radians(lat_a), math.radians(lat_b)
    dp = p2 - p1
    dl = math.radians(lon_b - lon_a)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def parse_evidence(payload: object, *, now: datetime, max_age_sec: int) -> Evidence:
    """Parse self-reported observation metadata; digest does not attest sensors."""
    if not isinstance(payload, dict) or not isinstance(payload.get("evidence"), dict):
        raise ValueError("EVIDENCE_MISSING")
    fields = payload["evidence"]
    event_id = fields.get("incident_id")
    kind = fields.get("event_class")
    digest = fields.get("sensor_sha256")
    if not isinstance(event_id, str) or not EVENT_ID_RE.fullmatch(event_id):
        raise ValueError("INCIDENT_ID_INVALID")
    if not isinstance(kind, str) or kind not in EVENT_CLASSES:
        raise ValueError("EVENT_CLASS_INVALID")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise ValueError("SENSOR_DIGEST_INVALID")
    observed_at = _utc_time(fields.get("observed_at"))
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("CLOCK_INVALID")
    skew = (now.astimezone(timezone.utc) - observed_at).total_seconds()
    if skew < -2 or skew > max_age_sec:
        raise ValueError("OBSERVATION_STALE")
    return Evidence(
        incident_id=event_id, event_class=kind, observed_at=observed_at,
        lat=_numeric(fields.get("lat"), "LAT", -90, 90),
        lon=_numeric(fields.get("lon"), "LON", -180, 180),
        sensor_sha256=digest,
    )


class EvidenceAdmissionGate:
    """Bounded quorum-over-independent-enrolled-session-identities policy.

    A malicious enrolled cohort can collude and pass quorum; source labels,
    sensor hashes, and incident IDs do not constitute hardware attestation.
    This module cannot substitute for cryptographic session verification.
    """

    def __init__(
        self, *, quorum: int = 2, max_distance_m: float = 100,
        max_time_delta_sec: float = 5, incident_ttl_sec: float = 20,
        max_incidents: int = 2048,
        clock: Callable[[], float] = time.monotonic,
        utc_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if isinstance(quorum, bool) or quorum < 2 or quorum > 16:
            raise ValueError("quorum must be 2..16")
        if not math.isfinite(max_distance_m) or not 1 <= max_distance_m <= 10000:
            raise ValueError("max_distance_m must be between 1 and 10000")
        if not math.isfinite(max_time_delta_sec) or not 0 < max_time_delta_sec <= 15:
            raise ValueError("max_time_delta_sec must be in (0, 15]")
        if not math.isfinite(incident_ttl_sec) or not 1 <= incident_ttl_sec <= 120:
            raise ValueError("incident_ttl_sec must be in [1, 120]")
        if isinstance(max_incidents, bool) or not 1 <= max_incidents <= 100000:
            raise ValueError("max_incidents must be in [1, 100000]")
        self.quorum = quorum
        self.max_distance_m = max_distance_m
        self.max_time_delta_sec = max_time_delta_sec
        self.incident_ttl_sec = incident_ttl_sec
        self.max_incidents = max_incidents
        self._clock, self._utc_clock = clock, utc_clock
        self._incidents: Dict[str, IncidentState] = {}
        self._lock = threading.Lock()
        self._counts = {"accepted": 0, "pending": 0, "rejected": 0, "already_accepted": 0}

    def _prune(self, now: float) -> None:
        for key, state in tuple(self._incidents.items()):
            if now - state.created_monotonic >= self.incident_ttl_sec:
                del self._incidents[key]

    def _result(self, status: str, reason: str, relayed: bool, count: int = 0, incident_id: str = "") -> AdmissionDecision:
        key = status if status in self._counts else "rejected"
        self._counts[key] += 1
        return AdmissionDecision(status, reason, relayed, count, incident_id)

    def snapshot(self) -> dict:
        """Counts only: excludes source IDs and raw incident/location data."""
        with self._lock:
            return {**self._counts, "active_incidents": len(self._incidents),
                    "quorum": self.quorum, "max_incidents": self.max_incidents}

    def evaluate(self, *, authenticated_sender_id: str, payload: object) -> AdmissionDecision:
        """Called only after hub's session MAC, identity and replay verification."""
        if not isinstance(authenticated_sender_id, str) or not EVENT_ID_RE.fullmatch(authenticated_sender_id):
            with self._lock:
                return self._result("rejected", "AUTHENTICATED_ID_REQUIRED", False)
        try:
            sample = parse_evidence(payload, now=self._utc_clock(), max_age_sec=MAX_EVENT_AGE_SECONDS)
        except (TypeError, ValueError) as exc:
            with self._lock:
                return self._result("rejected", str(exc), False)
        now = self._clock()
        with self._lock:
            self._prune(now)
            state = self._incidents.get(sample.incident_id)
            if state is None:
                if len(self._incidents) >= self.max_incidents:
                    return self._result("rejected", "INCIDENT_CAPACITY_REACHED", False)
                state = IncidentState(
                    observed_at=sample.observed_at, lat=sample.lat, lon=sample.lon,
                    event_class=sample.event_class, created_monotonic=now,
                )
                self._incidents[sample.incident_id] = state
            if state.event_class != sample.event_class:
                return self._result("rejected", "INCIDENT_CLASS_CONFLICT", False, len(state.reports), sample.incident_id)
            if abs((sample.observed_at - state.observed_at).total_seconds()) > self.max_time_delta_sec:
                return self._result("rejected", "INCIDENT_TIME_CONFLICT", False, len(state.reports), sample.incident_id)
            if _haversine_m(state.lat, state.lon, sample.lat, sample.lon) > self.max_distance_m:
                return self._result("rejected", "INCIDENT_LOCATION_CONFLICT", False, len(state.reports), sample.incident_id)
            if authenticated_sender_id in state.reports:
                return self._result("rejected", "REPEATED_IDENTITY", False, len(state.reports), sample.incident_id)
            if sample.sensor_sha256 in state.reports.values():
                return self._result("rejected", "DUPLICATE_SENSOR_DIGEST", False, len(state.reports), sample.incident_id)
            if state.accepted:
                return self._result("already_accepted", "INCIDENT_ALREADY_RELAYED", False, len(state.reports), sample.incident_id)
            state.reports[authenticated_sender_id] = sample.sensor_sha256
            if len(state.reports) >= self.quorum:
                state.accepted = True
                return self._result("accepted", "INDEPENDENT_REPORT_QUORUM", True, len(state.reports), sample.incident_id)
            return self._result("pending", "AWAITING_CORROBORATION", False, len(state.reports), sample.incident_id)
