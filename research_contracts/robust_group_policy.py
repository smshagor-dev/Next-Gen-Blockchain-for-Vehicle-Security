"""Non-actuating evidence quorum research comparator; never authorizes commands."""
from collections import defaultdict
from dataclasses import dataclass
from math import isfinite

@dataclass(frozen=True)
class Report:
    sender: str
    group: str
    incident: str
    timestamp: float
    hazard: bool
    authenticated: bool

@dataclass(frozen=True)
class Verdict:
    admitted: bool
    reason: str
    support_groups: int
    dissent_groups: int
    command_authorized: bool = False

def evaluate(reports, *, incident, now, min_groups=2, max_age=2., max_reports=64):
    """Require >=min_groups unconflicted supporting groups; dissent abstains.

    One group contributes at most one vote; a within-group conflict
    invalidates that group. This is not proof of witness independence.
    """
    if (type(now) not in (int,float) or not isfinite(now) or
        type(max_age) not in (int,float) or not 0 < max_age <= 60 or
        type(min_groups) is not int or not 2 <= min_groups <= 64 or
        type(max_reports) is not int or not 1 <= max_reports <= 256 or
        not isinstance(incident,str) or not incident):
        raise ValueError('invalid policy')
    if not isinstance(reports,(tuple,list)) or not reports or len(reports)>max_reports:
        return Verdict(False,'INVALID_REPORT_COUNT',0,0)
    seen=set(); groups=defaultdict(set)
    for r in reports:
        if (not isinstance(r,Report) or not r.sender or not r.group or
            r.incident != incident or type(r.timestamp) not in (int,float) or
            not isfinite(r.timestamp) or type(r.hazard) is not bool or
            type(r.authenticated) is not bool):
            return Verdict(False,'INVALID_REPORT',0,0)
        if not r.authenticated or r.sender in seen or not 0 <= now-r.timestamp <= max_age:
            return Verdict(False,'AUTH_REPLAY_OR_FRESHNESS_FAILURE',0,0)
        seen.add(r.sender);groups[r.group].add(r.hazard)
    support=sum(v=={True} for v in groups.values())
    dissent=sum(v=={False} for v in groups.values())
    return Verdict(support>=min_groups,
                   'QUORUM' if support>=min_groups else 'INSUFFICIENT_GROUPS',
                   support,dissent)
