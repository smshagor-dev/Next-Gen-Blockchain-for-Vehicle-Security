"""Isolated local experimental unit. No socket, vehicle or actuator access."""
from __future__ import annotations

import hashlib
import json
import os
import random
import secrets
import sys
import time
from datetime import datetime, timezone
from unittest.mock import patch

from experiments.claim_validation.claim_gate import evaluate_claim
from experiments.claim_validation.runtime_evidence import new_scope, observe_consensus, observe_identity, observe_handshake
from runtime_security_strength import evaluate_security_strength
from security_capabilities import security_capability_output
from identity_security import identity_security_metadata
from consensus_security import consensus_security_metadata


def point(value):
    return {"status": "ok", "value": value}


def snapshot(connection="Connected", identity=None, consensus=None, capabilities=None, alerts=()):
    return {"connection_status": point(connection),
            "security_capability": point(security_capability_output(False) if capabilities is None else capabilities),
            "identity_security": point(identity_security_metadata() if identity is None else identity),
            "consensus_security": point(consensus_security_metadata() if consensus is None else consensus),
            "runtime_alerts": list(alerts)}


def finish(claim, obs, scope, snap, declared, direct):
    posture = evaluate_security_strength(snap)["level"]
    start = time.perf_counter_ns()
    gate = evaluate_claim(claim, posture, obs, expected_scope=scope, now_ns=time.monotonic_ns())
    elapsed = time.perf_counter_ns() - start
    return {"claim": claim, "posture": posture, "declared": declared,
            "posture_proxy": posture == "STRONG",
            "declared_proxy": posture == "STRONG" and declared,
            "gate": gate.export(), "decision_ns": elapsed,
            "expected_scope": scope, "observation": obs.export(), "direct": direct}


def consensus_case(case):
    from permissioned_consensus import PermissionedConsensusEngine, ConsensusError, sign_vote
    n, num, den = (case[k] for k in ("n", "num", "den"))
    keys = {f"v{i}": secrets.token_hex(32) for i in range(n)}
    engine = PermissionedConsensusEngine(keys, epoch=3, quorum_numerator=num, quorum_denominator=den)
    scope = new_scope()
    pid = "heldout-proposal"
    phash = hashlib.sha256(scope.encode()).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    ids = list(keys)
    yes_ids = set(ids[:case["yes"]])
    random.Random(case["id"]).shuffle(ids)
    transitions = []
    error = ""
    def submit(voter, vote, epoch=3):
        sig = sign_vote(pid, phash, voter, vote, epoch, ts, keys[voter])
        result = engine.submit_vote(proposal_id=pid, proposal_hash=phash, voter_id=voter,
                                    vote=vote, epoch=epoch, proposal_timestamp=ts, vote_signature=sig)
        transitions.append({"voter": voter, "vote": vote, "status": result["status"],
                            "yes": result["yes_votes"], "no": result["no_votes"]})
        return result
    try:
        if case["mode"] == "wrong_epoch":
            submit(ids[0], True, 2)
        elif case["mode"] == "duplicate":
            submit(ids[0], True)
            submit(ids[0], True)
        else:
            for voter in ids:
                if submit(voter, voter in yes_ids)["status"] != "PENDING":
                    break
    except ConsensusError as exc:
        error = exc.reason
    tally = engine.tally(pid)
    meta = engine.metadata()
    obs = observe_consensus(engine, pid, scope)
    declared = (meta["validator_membership_enforced"] is True and
                meta["vote_signature_required"] is True and meta["quorum_basis"] == "configured_validator_set")
    return finish("recorded_quorum_acceptance", obs, scope, snapshot(consensus=meta), declared,
                  {"status": tally["status"], "error": error, "threshold": tally["quorum_threshold"],
                   "yes": tally["yes_votes"], "no": tally["no_votes"], "transitions": transitions})


def identity_case(case):
    import sync_protocol as sp
    from runtime_security_monitor import RuntimeSecurityMonitor
    size, challenge, compat = (case[k] for k in ("size", "challenge", "compat"))
    registry = {f"lab-enrolled-{i}": secrets.token_hex(32) for i in range(size)}
    global_key, wrong = secrets.token_hex(32), secrets.token_hex(32)
    identity = f"lab-enrolled-{case['replicate'] % size}" if size and challenge.startswith("enrolled") else "lab-unlisted"
    credential = registry[identity] if challenge == "enrolled_valid" else global_key if challenge == "unlisted_shared" else wrong
    policy = "TRANSPORT_AUTHORITY_REGISTRY" if size else "OPEN_REGISTRATION" if compat else "DENY_UNCONFIGURED"
    env = {"SMARTCAR_SYNC_VEHICLE_KEYS_JSON": json.dumps(registry),
           "SMARTCAR_SYNC_ALLOW_GLOBAL_PSK_ADMISSION": "1" if compat else "0",
           "SMARTCAR_IDENTITY_ADMISSION_POLICY": policy,
           "SMARTCAR_POA_AUTHORITY_REGISTRY_JSON": "{}", "SMARTCAR_SYNC_VALIDATOR_IDS": "",
           "SMARTCAR_SYNC_REPLAY_WINDOW_SEC": "15"}
    with patch.dict(os.environ, env):
        monitor = RuntimeSecurityMonitor()
        server = sp.SyncServer(host="127.0.0.1", shared_key=global_key,
                               vehicle_key_registry=registry, runtime_monitor=monitor)
        msg = {"type": sp.MessageType.HANDSHAKE,
               "payload": {"vehicle_id": identity, "client_version": "2.0"},
               "timestamp": sp._utc_now(), "nonce": sp._nonce()}
        msg["handshake_mac"] = sp._handshake_mac(credential, msg)
        response = server._process_message(msg, "heldout-session", "")
        ack_valid = False
        if response is not None:
            derived = sp._derive_session_key(credential, identity, msg["nonce"])
            ack = sp.verify_message(response.decode(), derived)
            ack_valid = bool(ack and ack["type"] == sp.MessageType.HANDSHAKE_ACK
                             and ack["payload"]["vehicle_id"] == identity)
        scope = new_scope()
        obs = observe_identity(server, "heldout-session", identity, ack_valid, scope)
        meta = identity_security_metadata()
        events = monitor.snapshot()["events"]
        return finish("enrolled_session", obs, scope,
                      snapshot(identity=meta, consensus=server.consensus_metadata(), alerts=events),
                      meta["sybil_resistance"] is True,
                      {"ack": ack_valid, "bound": server._bound_vehicle("heldout-session") == identity,
                       "registry_member": identity in registry, "registry_size": len(registry),
                       "event_reasons": [e["reason"] for e in events]})


def pqc_case(case):
    import v2x_protocol as v2x
    import cryptography
    import importlib.metadata
    from experiments.claim_validation.pqc_probe import require_providers
    require_providers()
    mode = case["mode"]
    classical = mode in ("ecdh", "psk")
    allow_ecdh = mode == "ecdh"
    env = {"SMARTCAR_V2X_FORCE_CLASSIC": "1" if classical else "0",
           "SMARTCAR_V2X_ALLOW_CLASSICAL_ECDH_FALLBACK": "1" if allow_ecdh else "0",
           "SMARTCAR_V2X_PQC_KEM_PREFERRED": "ML-KEM-512",
           "SMARTCAR_V2X_PQC_KEM_ALGS": "ML-KEM-512", "SMARTCAR_V2X_PQC_SIG_ALG": "ML-DSA-44"}
    with patch.dict(os.environ, env):
        secret, ctx = secrets.token_hex(32), secrets.token_hex(24)
        client = v2x.DynamicCryptoAgilityLayer("heldout-client", shared_secret=secret)
        server = v2x.DynamicCryptoAgilityLayer("heldout-server", shared_secret=secret)
        hello = client.handshake_hello_payload()
        ack = server.accept_handshake_as_server(hello, session_context="" if mode == "missing_context" else ctx)
        completed = client.complete_handshake_as_client(ack, session_context=secrets.token_hex(24) if mode == "context_mismatch" else ctx)
        scope = new_scope()
        obs = observe_handshake(client, server, completed, scope)
        # Independently check session identifiers and key agreement without exporting them.
        import hmac
        matched = bool(completed and client.session_established and server.session_established
                       and client._session_id == server._session_id
                       and hmac.compare_digest(client._session_key, server._session_key))
        caps = security_capability_output(allow_ecdh)
        return finish("mlkem512_session", obs, scope,
                      snapshot(connection="Connected" if matched else "Not Connected", capabilities=caps),
                      caps["key_establishment"] == "ML-KEM/Kyber - post-quantum",
                      {"mode": ack.get("hs_mode"), "client_mode": client._hs_mode,
                       "negotiated_kem": client._negotiated_kem_alg, "matched": matched,
                       "completed": completed, "liboqs": v2x.oqs.oqs_version(),
                       "binding_version": importlib.metadata.version("liboqs-python"),
                       "cryptography": cryptography.__version__})


def main():
    case = json.loads(sys.stdin.read())
    functions = {"consensus": consensus_case, "identity": identity_case, "pqc": pqc_case}
    result = functions[case["domain"]](case)
    print("HELDOUT_RESULT=" + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
