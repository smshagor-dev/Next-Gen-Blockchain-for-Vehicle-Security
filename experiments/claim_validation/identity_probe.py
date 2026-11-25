"""Local sync admission and metadata consistency pilot, no external endpoints."""
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import sync_protocol as sp
from identity_security import identity_security_metadata
from runtime_security_monitor import RuntimeSecurityMonitor
from runtime_security_strength import evaluate_security_strength
from security_capabilities import security_capability_output
from experiments.claim_validation.consensus_probe import BASELINE_SHA, ROOT, point, sha256
from experiments.claim_validation.runtime_evidence import new_scope, observe_identity
from experiments.claim_validation.claim_gate import evaluate_claim

# Configuration factors: registry presence, global compatibility flag, declared policy.
CONFIGS = {
    "registry_strict": (True, False, "TRANSPORT_AUTHORITY_REGISTRY"),
    "registry_with_compatibility": (True, True, "TRANSPORT_AUTHORITY_REGISTRY"),
    "unconfigured_deny": (False, False, "DENY_UNCONFIGURED"),
    "global_lab": (False, True, "OPEN_REGISTRATION"),
    "registry_declared_open": (True, False, "OPEN_REGISTRATION"),
    "global_declared_deny": (False, True, "DENY_UNCONFIGURED"),
}
CHALLENGES = ("enrolled_valid", "enrolled_wrong", "unlisted_shared", "unlisted_wrong")
REPEATS = 4


def trial(config, challenge, repeat):
    registry_present, allow_global, policy = CONFIGS[config]
    global_key = secrets.token_hex(32)
    enrolled_key = secrets.token_hex(32)
    wrong_key = secrets.token_hex(32)
    registry = {"lab-enrolled": enrolled_key} if registry_present else {}
    identity = "lab-enrolled" if challenge.startswith("enrolled") else "lab-unlisted"
    credential = {"enrolled_valid": enrolled_key, "enrolled_wrong": wrong_key,
                  "unlisted_shared": global_key, "unlisted_wrong": wrong_key}[challenge]
    monitor = RuntimeSecurityMonitor()
    config_env = {
        "SMARTCAR_SYNC_VEHICLE_KEYS_JSON": json.dumps(registry),
        "SMARTCAR_SYNC_ALLOW_GLOBAL_PSK_ADMISSION": "1" if allow_global else "0",
        "SMARTCAR_IDENTITY_ADMISSION_POLICY": policy,
        "SMARTCAR_POA_AUTHORITY_REGISTRY_JSON": "{}",
        "SMARTCAR_SYNC_VALIDATOR_IDS": "",
        "SMARTCAR_SYNC_REPLAY_WINDOW_SEC": "15",
    }
    with patch.dict(os.environ, config_env):
        server = sp.SyncServer(host="127.0.0.1", shared_key=global_key,
                               vehicle_key_registry=registry, runtime_monitor=monitor)
        identity_meta = identity_security_metadata()
        before = {"connection_status": point("Connected"),
                  "security_capability": point(security_capability_output(False)),
                  "identity_security": point(identity_meta),
                  "consensus_security": point(server.consensus_metadata())}
        msg = {"type": sp.MessageType.HANDSHAKE,
               "payload": {"vehicle_id": identity, "client_version": "2.0"},
               "timestamp": sp._utc_now(), "nonce": sp._nonce()}
        msg["handshake_mac"] = sp._handshake_mac(credential, msg)
        start = time.perf_counter_ns()
        response = server._process_message(msg, "lab-session", "")
        elapsed = time.perf_counter_ns() - start
        bound = server._bound_vehicle("lab-session") == identity
        ack_valid = False
        if response is not None:
            derived = sp._derive_session_key(credential, identity, msg["nonce"])
            ack = sp.verify_message(response.decode(), derived)
            ack_valid = bool(ack and ack["type"] == sp.MessageType.HANDSHAKE_ACK
                             and ack["payload"]["vehicle_id"] == identity)
        scope = new_scope()
        observation = observe_identity(server, "lab-session", identity, ack_valid, scope)
        evidence = observation.export()
        events = monitor.snapshot()["events"]
        # Compare constructed dashboard wrappers with and without observed alert events.
        with_alerts = dict(before, runtime_alerts=events)
        gate = evaluate_claim("enrolled_session", evaluate_security_strength(with_alerts)["level"],
                              observation, expected_scope=scope, now_ns=time.monotonic_ns()).export()
        return {
            "config": config, "challenge": challenge, "repeat": repeat,
            "registry_present": registry_present, "global_compatibility": allow_global,
            "declared_policy": policy, "identity_admission_enforced_metadata": identity_meta["identity_admission_enforced"],
            "sybil_resistance_metadata": identity_meta["sybil_resistance"],
            "registry_count_metadata": identity_meta["admission_registry_identity_count"],
            "authenticated_ack": ack_valid, "bound_identity": bound,
            "unlisted_identity_accepted": ack_valid and identity not in registry,
            "posture_without_alerts": evaluate_security_strength(before)["level"],
            "posture_with_observed_alerts": evaluate_security_strength(with_alerts)["level"],
            "observed_reasons": [event["reason"] for event in events],
            "runtime_evidence": evidence, "expected_scope": scope,
            "claim_gate": gate, "elapsed_ns": elapsed,
        }


def write_campaign(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    rows = [trial(config, challenge, repeat)
            for config in CONFIGS for challenge in CHALLENGES for repeat in range(REPEATS)]
    trace = out / "traces.jsonl"
    trace.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    decisions = out / "decisions.csv"
    fields = [key for key in rows[0] if key not in ("observed_reasons", "runtime_evidence", "claim_gate")]
    with decisions.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    cells = []
    for config in CONFIGS:
        for challenge in CHALLENGES:
            group = [row for row in rows if row["config"] == config and row["challenge"] == challenge]
            cells.append({"config": config, "challenge": challenge, "runs": len(group),
                          "authenticated_acks": sum(row["authenticated_ack"] for row in group),
                          "unlisted_acceptances": sum(row["unlisted_identity_accepted"] for row in group),
                          "strong_without_alerts": sum(row["posture_without_alerts"] == "STRONG" for row in group),
                          "strong_with_alerts": sum(row["posture_with_observed_alerts"] == "STRONG" for row in group),
                          "enrolled_claim_eligible": sum(row["claim_gate"]["eligibility"] == "ELIGIBLE" for row in group)})
    result = {"rows": len(rows), "cells": cells, "exploratory_only": True, "statistical_inference": False}
    summary = out / "summary.json"
    summary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    sources = ("sync_protocol.py", "sync_protocol_legacy.py", "identity_security.py",
               "runtime_security_monitor.py", "runtime_security_strength.py", "security_capabilities.py",
               "permissioned_consensus.py", "replay_security.py", "env_config.py",
               "zkp_privacy.py", "release_metadata.py", "VERSION",
               "experiments/claim_validation/identity_probe.py", "experiments/claim_validation/consensus_probe.py",
               "experiments/claim_validation/runtime_evidence.py", "experiments/claim_validation/claim_gate.py")
    manifest = {"schema": "claim-validity-identity-pilot/1", "baseline_sha": BASELINE_SHA,
                "executed_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "python": sys.version, "platform": platform.platform(),
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "source_sha256": {name: sha256(ROOT / name) for name in sources},
                "artifact_sha256": {p.name: sha256(p) for p in (trace, decisions, summary)},
                "scope": "actual local sync handler and authenticated ACK, constructed dashboard wrapper",
                "repeats": REPEATS, "socket_network_executed": False, "publication_ready": False}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    write_campaign(parser.parse_args().out)
