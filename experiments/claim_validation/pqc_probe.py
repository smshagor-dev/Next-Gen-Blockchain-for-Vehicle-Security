"""Actual liboqs-backed Python handshake pilot, not native C++ or wireless testing."""
from __future__ import annotations

import argparse
import hashlib
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
from contextlib import nullcontext

import v2x_protocol as v2x
from security_capabilities import security_capability_output
from identity_security import identity_security_metadata
from consensus_security import consensus_security_metadata
from runtime_security_strength import evaluate_security_strength
from experiments.claim_validation.consensus_probe import BASELINE_SHA, ROOT, point, sha256
from experiments.claim_validation.runtime_evidence import new_scope, observe_handshake
from experiments.claim_validation.claim_gate import evaluate_claim

CONFIGS = {
    "native_mlkem": (False, False, False, False),
    "forced_classical_ecdh": (True, True, False, False),
    "forced_classical_psk": (True, False, False, False),
    "provider_missing_ecdh": (False, True, True, False),
    "provider_missing_psk": (False, False, True, False),
    "malformed_kem_psk": (False, False, False, True),
}
REPEATS = 8


def require_providers():
    if v2x.oqs is None or not v2x.CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("real liboqs and cryptography are required; no simulated positive result")
    if "ML-KEM-512" not in v2x.oqs.get_enabled_kem_mechanisms():
        raise RuntimeError("ML-KEM-512 not enabled")


def trial(config, repeat):
    force_classic, allow_ecdh, missing_provider, corrupt_hello = CONFIGS[config]
    secret = secrets.token_hex(32)
    ctx = secrets.token_hex(24)
    env = {
        "SMARTCAR_V2X_FORCE_CLASSIC": "1" if force_classic else "0",
        "SMARTCAR_V2X_ALLOW_CLASSICAL_ECDH_FALLBACK": "1" if allow_ecdh else "0",
        "SMARTCAR_V2X_PQC_KEM_PREFERRED": "ML-KEM-512",
        "SMARTCAR_V2X_PQC_KEM_ALGS": "ML-KEM-512",
        "SMARTCAR_V2X_PQC_SIG_ALG": "ML-DSA-44",
    }
    # Deliberate provider-unavailability injection, not a native library failure.
    provider = patch.object(v2x, "oqs", None) if missing_provider else nullcontext()
    with patch.dict(os.environ, env), provider:
        start = time.perf_counter_ns()
        client = v2x.DynamicCryptoAgilityLayer("lab-client", shared_secret=secret)
        server = v2x.DynamicCryptoAgilityLayer("lab-server", shared_secret=secret)
        hello = client.handshake_hello_payload()
        offered_kem = hello.get("kem_alg", "")
        if corrupt_hello:
            if offered_kem != "ML-KEM-512":
                raise RuntimeError("malformed-input control requires a real offered KEM")
            hello["kem_pubkey"] = "invalid-hex"
        ack = server.accept_handshake_as_server(hello, session_context=ctx)
        complete = client.complete_handshake_as_client(ack, session_context=ctx)
        elapsed = time.perf_counter_ns() - start
        scope = new_scope()
        observation = observe_handshake(client, server, complete, scope)
        evidence = observation.export()
        matched = evidence["facts"]["matched_session"]
        # Never export keys, public key material, transcript context or secret.
        declared = security_capability_output(allow_ecdh)
        snapshot = {"connection_status": point("Connected" if matched else "Not Connected"),
                    "security_capability": point(declared),
                    "identity_security": point(identity_security_metadata()),
                    "consensus_security": point(consensus_security_metadata())}
        gate = evaluate_claim("mlkem512_session", evaluate_security_strength(snapshot)["level"],
                              observation, expected_scope=scope, now_ns=time.monotonic_ns()).export()
        return {"config": config, "repeat": repeat,
                "provider_unavailability_injected": missing_provider,
                "malformed_hello_injected": corrupt_hello,
                "offered_kem": offered_kem, "server_mode": ack.get("hs_mode"),
                "client_mode": client._hs_mode, "negotiated_kem": client._negotiated_kem_alg,
                "matched_session": matched,
                "declared_key_establishment": declared["key_establishment"],
                "operational_posture": evaluate_security_strength(snapshot)["level"],
                "observed_mlkem_session": matched and client._hs_mode == "PQC_KEM"
                    and client._negotiated_kem_alg == "ML-KEM-512",
                "runtime_evidence": evidence, "expected_scope": scope,
                "claim_gate": gate, "elapsed_ns": elapsed}


def write_campaign(out: Path):
    require_providers()
    out.mkdir(parents=True, exist_ok=True)
    rows = [trial(config, repeat) for config in CONFIGS for repeat in range(REPEATS)]
    trace = out / "traces.jsonl"
    trace.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    cells = []
    for config in CONFIGS:
        group = [row for row in rows if row["config"] == config]
        cells.append({"config": config, "runs": len(group),
                      "matched_sessions": sum(r["matched_session"] for r in group),
                      "observed_mlkem_sessions": sum(r["observed_mlkem_session"] for r in group),
                      "ecdh_sessions": sum(r["matched_session"] and r["client_mode"] == "ECDH" for r in group),
                      "psk_sessions": sum(r["matched_session"] and r["client_mode"] == "PSK" for r in group),
                      "strong": sum(r["operational_posture"] == "STRONG" for r in group),
                      "mlkem_claim_eligible": sum(r["claim_gate"]["eligibility"] == "ELIGIBLE" for r in group)})
    result = {"rows": len(rows), "cells": cells, "exploratory_only": True,
              "statistical_inference": False}
    summary = out / "summary.json"
    summary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    sources = ("v2x_protocol.py", "security_capabilities.py", "identity_security.py",
               "consensus_security.py", "runtime_security_strength.py", "env_config.py",
               "v2x_evidence_admission.py", "release_metadata.py", "VERSION",
               "experiments/claim_validation/pqc_probe.py", "experiments/claim_validation/consensus_probe.py",
               "experiments/claim_validation/runtime_evidence.py", "experiments/claim_validation/claim_gate.py")
    import cryptography
    import importlib.metadata
    manifest = {"schema": "claim-validity-pqc-pilot/1", "baseline_sha": BASELINE_SHA,
                "executed_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "python": sys.version, "platform": platform.platform(), "liboqs": v2x.oqs.oqs_version(),
                "liboqs_python": importlib.metadata.version("liboqs-python"),
                "cryptography": cryptography.__version__, "created_utc": datetime.now(timezone.utc).isoformat(),
                "source_sha256": {name: sha256(ROOT / name) for name in sources},
                "artifact_sha256": {p.name: sha256(p) for p in (trace, summary)},
                "scope": "actual Python handshake with native crypto provider, constructed dashboard wrapper",
                "native_cpp_executed": False, "socket_network_executed": False,
                "publication_ready": False}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    write_campaign(parser.parse_args().out)
