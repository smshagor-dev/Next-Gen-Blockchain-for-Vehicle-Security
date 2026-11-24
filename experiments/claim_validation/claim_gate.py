"""Research-only, claim-specific eligibility policy for trusted local observations.

Never authorizes commands and never interprets STRONG as proof. The caller
must trust the same-process observer and supply its expected trial scope.
An exported digest is not authentication. Validator honesty and external
policy validity are not observable from a tally, so they remain withheld.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from experiments.claim_validation.runtime_evidence import Observation, SCHEMAS, is_current

CLAIM_KIND = {
    "mlkem512_session": "handshake",
    "enrolled_session": "identity",
    "recorded_quorum_acceptance": "consensus",
    "honest_validator_quorum": "consensus",
    "external_policy_validity": "consensus",
}
DEFAULT_MAX_AGE_NS = 1_000_000_000


@dataclass(frozen=True)
class ClaimDecision:
    claim: str
    operational_posture: str
    eligibility: str
    reason: str
    trust_boundary: str = "local_observer_same_process"

    def export(self):
        return asdict(self)


def _facts(observation):
    if type(observation.facts) is not tuple:
        return None
    schema = SCHEMAS[observation.kind]
    if len(observation.facts) != len(schema):
        return None
    facts = {}
    for pair in observation.facts:
        if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str:
            return None
        key, value = pair
        if key not in schema or key in facts or type(value) is not schema[key]:
            return None
        if type(value) is int and value < 0:
            return None
        facts[key] = value
    return facts


def evaluate_claim(claim, posture, observation, *, expected_scope, now_ns,
                   max_age_ns=DEFAULT_MAX_AGE_NS):
    if type(claim) is not str or claim not in CLAIM_KIND:
        raise ValueError("unknown claim")
    if type(posture) is not str or posture not in {"STRONG", "GUARDED", "DEGRADED", "RISK"}:
        raise ValueError("invalid operational posture")
    def decision(status, reason):
        return ClaimDecision(claim, posture, status, reason)

    if observation is None:
        return decision("WITHHELD", "EVIDENCE_MISSING")
    if not is_current(observation, kind=CLAIM_KIND[claim], scope=expected_scope,
                      now_ns=now_ns, max_age_ns=max_age_ns):
        return decision("WITHHELD", "EVIDENCE_SCOPE_KIND_OR_FRESHNESS_INVALID")
    if (type(expected_scope) is not str or len(expected_scope) != 32
            or any(c not in "0123456789abcdef" for c in expected_scope)):
        return decision("WITHHELD", "EVIDENCE_SCOPE_INVALID")
    facts = _facts(observation)
    if facts is None:
        return decision("WITHHELD", "EVIDENCE_SCHEMA_INVALID")

    if observation.kind == "handshake":
        modes = {"NONE", "PSK", "ECDH", "PQC_KEM"}
        if (facts["client_mode"] not in modes or facts["server_mode"] not in modes
                or (facts["matched_session"] and
                    (not facts["completed"] or facts["client_mode"] != facts["server_mode"]
                     or facts["client_mode"] == "NONE"))):
            return decision("WITHHELD", "EVIDENCE_INCONSISTENT")
        if not (facts["completed"] and facts["matched_session"]):
            return decision("WITHHELD", "SESSION_NOT_CONFIRMED")
        if not (facts["client_mode"] == facts["server_mode"] == "PQC_KEM"
                and facts["negotiated_kem"] == "ML-KEM-512"):
            return decision("NOT_SUPPORTED", "MLKEM512_NOT_NEGOTIATED")
    elif observation.kind == "identity":
        if (facts["bound"] != facts["authenticated_ack"]
                or (facts["registry_member"] and facts["registry_size"] == 0)):
            return decision("WITHHELD", "EVIDENCE_INCONSISTENT")
        if not facts["authenticated_ack"]:
            return decision("NOT_SUPPORTED", "SESSION_NOT_ADMITTED")
        if not facts["registry_member"]:
            return decision("NOT_SUPPORTED", "ADMITTED_IDENTITY_NOT_ENROLLED")
    else:
        n, q, yes, no = (facts[k] for k in
                         ("validator_count", "quorum_threshold", "yes_votes", "no_votes"))
        if (facts["epoch"] < 1 or not 1 <= q <= n or yes + no > n
                or facts["status"] not in {"ACCEPTED", "REJECTED", "PENDING", "UNKNOWN"}
                or (facts["status"] == "ACCEPTED") != (yes >= q)
                or (facts["status"] == "REJECTED") != (no > n-q)
                or (facts["status"] == "UNKNOWN" and yes + no != 0)):
            return decision("WITHHELD", "EVIDENCE_INCONSISTENT")
        if claim in {"honest_validator_quorum", "external_policy_validity"}:
            return decision("WITHHELD", "ASSUMPTION_NOT_OBSERVABLE_FROM_TALLY")
        if facts["status"] != "ACCEPTED":
            return decision("NOT_SUPPORTED", "QUORUM_ACCEPTANCE_NOT_RECORDED")

    if posture != "STRONG":
        return decision("WITHHELD", "OPERATIONAL_POSTURE_NOT_STRONG")
    return decision("ELIGIBLE", "SCOPED_OBSERVATION_SUPPORTS_CLAIM")
