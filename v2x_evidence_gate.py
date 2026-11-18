"""Research prototype: independent evidence-gated V2X event admission.

Inputs MUST already be authenticated by the transport layer. Witness identity
and trust-group enrollment MUST be independently verified by the caller.
No vehicle command is generated or authorized by this module.
"""
from dataclasses import dataclass
from math import isfinite
from typing import FrozenSet, Tuple


@dataclass(frozen=True)
class Observation:
    sender: str
    trust_group: str
    incident: str
    observed_at: float
    hazard: bool
    authenticated: bool


@dataclass(frozen=True)
class AdmissionDecision:
    admitted: bool
    reason: str
    distinct_groups: int
    supporting_senders: Tuple[str, ...]
    command_authorized: bool = False


def admit_hazard(
    target: Observation,
    witnesses: tuple[Observation, ...],
    *,
    now: float,
    max_age_seconds: float = 2.0,
    max_clock_skew_seconds: float = 0.1,
    minimum_independent_groups: int = 2,
    max_witnesses: int = 64,
) -> AdmissionDecision:
    """Fail closed on unauthenticated, stale, conflicted, or correlated evidence.

    A trust group models a shared failure/compromise domain, not a cryptographic
    identity. Two devices from the same group never count as independent.
    This gate only permits *ledger event admission*, never physical actuation.
    """
    if (type(now) not in (int, float) or not isfinite(now)
            or type(max_age_seconds) not in (int, float) or not 0 < max_age_seconds <= 60
            or type(max_clock_skew_seconds) not in (int, float) or not 0 <= max_clock_skew_seconds <= 5
            or type(minimum_independent_groups) is not int
            or not 2 <= minimum_independent_groups <= 64
            or type(max_witnesses) is not int or not 1 <= max_witnesses <= 256):
        raise ValueError("invalid admission policy")
    if len(witnesses) > max_witnesses:
        return AdmissionDecision(False, "WITNESS_BUDGET_EXCEEDED", 0, ())
    all_observations = (target,) + tuple(witnesses)
    seen_senders = set()
    groups = {}
    for item in all_observations:
        if (not isinstance(item, Observation) or type(item.sender) is not str
                or not item.sender or type(item.trust_group) is not str
                or not item.trust_group or type(item.incident) is not str
                or not item.incident or type(item.hazard) is not bool
                or type(item.authenticated) is not bool
                or type(item.observed_at) not in (int, float)
                or not isfinite(item.observed_at)):
            return AdmissionDecision(False, "INVALID_EVIDENCE", 0, ())
        if not item.authenticated:
            return AdmissionDecision(False, "UNAUTHENTICATED_EVIDENCE", 0, ())
        if item.sender in seen_senders:
            return AdmissionDecision(False, "DUPLICATE_SENDER", 0, ())
        seen_senders.add(item.sender)
        if item.incident != target.incident:
            return AdmissionDecision(False, "INCIDENT_MISMATCH", 0, ())
        age = now - item.observed_at
        if age < -max_clock_skew_seconds or age > max_age_seconds:
            return AdmissionDecision(False, "EVIDENCE_OUT_OF_WINDOW", 0, ())
        if item.trust_group in groups:
            if groups[item.trust_group].hazard != item.hazard:
                return AdmissionDecision(False, "WITHIN_GROUP_CONFLICT", 0, ())
        else:
            groups[item.trust_group] = item
    if not target.hazard:
        return AdmissionDecision(False, "TARGET_NOT_HAZARD", 0, ())
    if any(not obs.hazard for obs in groups.values()):
        return AdmissionDecision(False, "CONTRADICTORY_EVIDENCE", 0, ())
    supporting = tuple(sorted(obs.sender for obs in groups.values()))
    if len(groups) < minimum_independent_groups:
        return AdmissionDecision(False, "INSUFFICIENT_INDEPENDENT_GROUPS", len(groups), supporting)
    return AdmissionDecision(True, "INDEPENDENT_HAZARD_CORROBORATION", len(groups), supporting)
