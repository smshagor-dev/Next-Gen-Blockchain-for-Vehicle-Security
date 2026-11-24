"""Evidence acquisition independent of posture metadata, local research scope.

The observer reads actual component outcomes rather than declared capabilities
or experimental policy labels. It is not a separate security principal, remote
attestation, or proof of physical identity/validator honesty. SHA256 binds an
exported record to its bytes, not to an independently trusted origin.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any


SCHEMAS = {
    "handshake": {"completed": bool, "matched_session": bool, "client_mode": str,
                  "server_mode": str, "negotiated_kem": str},
    "identity": {"bound": bool, "authenticated_ack": bool, "registry_member": bool,
                 "registry_size": int},
    "consensus": {"epoch": int, "validator_count": int, "quorum_threshold": int,
                  "yes_votes": int, "no_votes": int, "status": str},
}


def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class Observation:
    kind: str
    scope: str
    monotonic_ns: int
    facts: tuple[tuple[str, Any], ...]

    def export(self):
        body = {"schema": "runtime-observation/1", "kind": self.kind,
                "scope": self.scope, "monotonic_ns": self.monotonic_ns,
                "facts": dict(self.facts),
                "trust_boundary": "local_observer_same_process"}
        return {**body, "sha256": hashlib.sha256(canonical(body)).hexdigest()}


def new_scope():
    return secrets.token_hex(16)


def _record(kind, scope, facts):
    if (type(scope) is not str or len(scope) != 32
            or any(c not in "0123456789abcdef" for c in scope)):
        raise ValueError("invalid observation scope")
    schema = SCHEMAS[kind]
    if set(facts) != set(schema) or any(type(facts[k]) is not t for k, t in schema.items()):
        raise ValueError("invalid observation facts")
    if any(type(v) is int and v < 0 for v in facts.values()):
        raise ValueError("negative observation count")
    return Observation(kind, scope, time.monotonic_ns(), tuple(sorted(facts.items())))


def observe_handshake(client, server, completed, scope):
    matched = bool(completed and client.session_established and server.session_established
                   and client._session_id == server._session_id
                   and hmac.compare_digest(client._session_key, server._session_key))
    return _record("handshake", scope, {
        "completed": completed, "matched_session": matched,
        "client_mode": client._hs_mode, "server_mode": server._hs_mode,
        "negotiated_kem": client._negotiated_kem_alg,
    })


def observe_identity(server, client_id, expected_identity, ack_valid, scope):
    bound = server._bound_vehicle(client_id) == expected_identity
    if bound != ack_valid:
        raise ValueError("binding and authenticated acknowledgement disagree")
    return _record("identity", scope, {
        "bound": bound, "authenticated_ack": ack_valid,
        "registry_member": expected_identity in server.vehicle_key_registry,
        "registry_size": len(server.vehicle_key_registry),
    })


def observe_consensus(engine, proposal_id, scope):
    tally = engine.tally(proposal_id)
    return _record("consensus", scope, {
        "epoch": tally["epoch"], "validator_count": tally["validator_count"],
        "quorum_threshold": tally["quorum_threshold"], "yes_votes": tally["yes_votes"],
        "no_votes": tally["no_votes"], "status": tally["status"],
    })


def is_current(observation, *, kind, scope, now_ns, max_age_ns):
    """In-process lifetime check, not cross-host time or durable anti-replay."""
    if (type(observation) is not Observation or observation.kind != kind
            or observation.scope != scope or type(now_ns) is not int
            or type(max_age_ns) is not int or max_age_ns <= 0
            or type(observation.monotonic_ns) is not int):
        return False
    return 0 <= now_ns - observation.monotonic_ns <= max_age_ns
