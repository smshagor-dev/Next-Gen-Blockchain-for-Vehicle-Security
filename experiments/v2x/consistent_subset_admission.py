"""Research-only order-resistant V2X incident corroboration ablation.

Unlike the production prototype, no single report pins an incident's reference
location or time. A relay requires a mutually consistent subset of distinct
already-authenticated enrolled node identities. This is an experimental
comparison only: NOT wired into V2XHub, not a new cryptographic primitive,
not Sybil resistant and not authorized for physical vehicle control.

Worst-case combinatorial work is explicitly bounded by max_reports<=16 and
quorum<=4. Enrolled colluders can still form a self-consistent false quorum;
an attacker can still exhaust per-incident capacity. Neither is solved here.
"""
from __future__ import annotations

import itertools
import math
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from v2x_evidence_admission import (
    AUTH_ID_RE, AdmissionDecision, Evidence, _haversine_m, parse_evidence,
)


@dataclass
class PendingIncident:
    created: float
    event_class: str
    reports: dict[str, Evidence] = field(default_factory=dict)
    accepted: bool = False
    accepted_sources: tuple[str, ...] = ()


class ConsistentSubsetAdmissionGate:
    def __init__(
        self, *, quorum: int = 2, max_reports: int = 16,
        max_incidents: int = 2048, incident_ttl_sec: float = 20,
        max_distance_m: float = 100, max_time_delta_sec: float = 5,
        clock: Callable[[], float] = time.monotonic,
        utc_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if type(quorum) is not int or not 2 <= quorum <= 4:
            raise ValueError("research quorum must be an integer 2..4")
        if type(max_reports) is not int or not quorum <= max_reports <= 16:
            raise ValueError("max_reports must be between quorum and 16")
        if type(max_incidents) is not int or not 1 <= max_incidents <= 100000:
            raise ValueError("invalid max_incidents")
        if not math.isfinite(incident_ttl_sec) or not 1 <= incident_ttl_sec <= 120:
            raise ValueError("invalid TTL")
        if not math.isfinite(max_distance_m) or not 1 <= max_distance_m <= 10000:
            raise ValueError("invalid distance tolerance")
        if not math.isfinite(max_time_delta_sec) or not 0 < max_time_delta_sec <= 15:
            raise ValueError("invalid time tolerance")
        self.quorum = quorum
        self.max_reports = max_reports
        self.max_incidents = max_incidents
        self.ttl = incident_ttl_sec
        self.distance = max_distance_m
        self.time_delta = max_time_delta_sec
        self._clock = clock
        self._utc_clock = utc_clock
        self._incidents: dict[str, PendingIncident] = {}
        self._lock = threading.Lock()
        self._counters = {"accepted": 0, "pending": 0, "rejected": 0, "already_accepted": 0}

    def _decision(self, status: str, reason: str, relay: bool,
                  count: int, incident_id: str) -> AdmissionDecision:
        self._counters[status] += 1
        return AdmissionDecision(
            status=status, reason=reason, relayed=relay,
            independent_sources=count, incident_id=incident_id,
        )

    def snapshot(self) -> dict:
        with self._lock:
            return {
                **self._counters, "active_incidents": len(self._incidents),
                "max_reports_per_incident": self.max_reports, "quorum": self.quorum,
            }

    def accepted_sources_for(self, incident_id: str) -> tuple[str, ...]:
        """Return exact research-only voters for an admitted incident."""
        with self._lock:
            state = self._incidents.get(incident_id)
            return state.accepted_sources if state and state.accepted else ()

    def _mutually_consistent(self, candidates: tuple[Evidence, ...]) -> bool:
        return all(
            a.event_class == b.event_class
            and abs((a.observed_at - b.observed_at).total_seconds()) <= self.time_delta
            and _haversine_m(a.lat, a.lon, b.lat, b.lon) <= self.distance
            for a, b in itertools.combinations(candidates, 2)
        )

    def evaluate(self, *, authenticated_sender_id: str,
                 payload: object) -> AdmissionDecision:
        """Precondition: V2X hub independently verified session MAC and replay."""
        if (not isinstance(authenticated_sender_id, str)
                or not AUTH_ID_RE.fullmatch(authenticated_sender_id)):
            with self._lock:
                return self._decision("rejected", "AUTHENTICATED_ID_REQUIRED", False, 0, "")
        try:
            sample = parse_evidence(
                payload, now=self._utc_clock(), max_age_sec=15
            )
        except (TypeError, ValueError) as exc:
            with self._lock:
                return self._decision("rejected", str(exc), False, 0, "")
        now = self._clock()
        with self._lock:
            for incident_id, current in tuple(self._incidents.items()):
                if now - current.created >= self.ttl:
                    del self._incidents[incident_id]
            state = self._incidents.get(sample.incident_id)
            if state is None:
                if len(self._incidents) >= self.max_incidents:
                    return self._decision(
                        "rejected", "INCIDENT_CAPACITY_REACHED", False, 0, sample.incident_id
                    )
                state = PendingIncident(created=now, event_class=sample.event_class)
                self._incidents[sample.incident_id] = state
            if state.event_class != sample.event_class:
                return self._decision(
                    "rejected", "INCIDENT_CLASS_CONFLICT", False,
                    len(state.reports), sample.incident_id,
                )
            if state.accepted:
                return self._decision(
                    "already_accepted", "INCIDENT_ALREADY_RELAYED", False,
                    len(state.reports), sample.incident_id,
                )
            if authenticated_sender_id in state.reports:
                return self._decision(
                    "rejected", "REPEATED_IDENTITY", False,
                    len(state.reports), sample.incident_id,
                )
            if any(old.sensor_sha256 == sample.sensor_sha256 for old in state.reports.values()):
                return self._decision(
                    "rejected", "DUPLICATE_SENSOR_DIGEST", False,
                    len(state.reports), sample.incident_id,
                )
            if len(state.reports) >= self.max_reports:
                return self._decision(
                    "rejected", "INCIDENT_REPORT_CAPACITY_REACHED", False,
                    len(state.reports), sample.incident_id,
                )
            state.reports[authenticated_sender_id] = sample
            # No first-reporter location/time reference; all candidate reports
            # must be mutually consistent. The small bounded pool avoids
            # unlimited subset enumeration.
            for sources in itertools.combinations(state.reports, self.quorum):
                reports = tuple(state.reports[sender] for sender in sources)
                if self._mutually_consistent(reports):
                    state.accepted = True
                    state.accepted_sources = tuple(sources)
                    return self._decision(
                        "accepted", "MUTUALLY_CONSISTENT_ENROLLED_SUBSET", True,
                        len(sources), sample.incident_id,
                    )
            return self._decision(
                "pending", "AWAITING_CONSISTENT_SUBSET", False,
                len(state.reports), sample.incident_id,
            )
