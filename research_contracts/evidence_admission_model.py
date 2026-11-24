"""Offline deterministic V2X admission model; never actuates."""
from dataclasses import dataclass
import math

@dataclass(frozen=True)
class Observation:
    source: str
    event: str
    timestamp: float
    authenticated: bool
    evidence_valid: bool
    domain: str

@dataclass(frozen=True)
class Decision:
    admitted: bool
    reason: str
    remote_actuation_authorized: bool = False

def decide(observations, now, *, max_age=2.0, min_domains=2, require_evidence=True, require_freshness=True):
    if type(now) not in (int, float) or not math.isfinite(now):
        return Decision(False, 'invalid_clock')
    if type(max_age) not in (int, float) or not math.isfinite(max_age) or max_age <= 0 or type(min_domains) is not int or min_domains < 1:
        return Decision(False, 'invalid_policy')
    if not observations:
        return Decision(False, 'no_observations')
    sources, domains, events = set(), set(), set()
    for o in observations:
        if not isinstance(o, Observation) or not o.source or not o.domain or not o.event:
            return Decision(False, 'malformed_observation')
        if type(o.authenticated) is not bool or type(o.evidence_valid) is not bool:
            return Decision(False, 'malformed_observation')
        if o.source in sources:
            return Decision(False, 'duplicate_source')
        sources.add(o.source)
        if not o.authenticated:
            return Decision(False, 'unauthenticated')
        if require_evidence and not o.evidence_valid:
            return Decision(False, 'invalid_evidence')
        if require_freshness and (type(o.timestamp) not in (int, float) or not math.isfinite(o.timestamp) or o.timestamp > now or now-o.timestamp > max_age):
            return Decision(False, 'stale_or_future')
        domains.add(o.domain)
        events.add(o.event)
    if len(events) != 1:
        return Decision(False, 'conflicting_event')
    if len(domains) < min_domains:
        return Decision(False, 'insufficient_independent_domains')
    return Decision(True, 'evidence_admitted')

def signature_only(observations, now):
    return decide(observations, now, min_domains=1, require_evidence=False, require_freshness=False)

def quorum_only(observations, now, min_domains=2):
    return decide(observations, now, min_domains=min_domains, require_evidence=False, require_freshness=False)
