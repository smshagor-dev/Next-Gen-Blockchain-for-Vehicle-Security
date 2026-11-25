"""Exploratory actual-engine claim-validity experiment; not a field trial."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import random
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from permissioned_consensus import PermissionedConsensusEngine, sign_vote
from runtime_security_strength import evaluate_security_strength
from security_capabilities import security_capability_output
from identity_security import identity_security_metadata
from experiments.claim_validation.runtime_evidence import new_scope, observe_consensus
from experiments.claim_validation.claim_gate import evaluate_claim

BASELINE_SHA = "0e3429a8bf6338ff99779dbc7cc4aa61972932ee"
SEEDS = tuple(range(12))
ROOT = Path(__file__).resolve().parents[2]


def point(value):
    return {"status": "ok", "value": value}


def trial(seed: int, controlled_yes: int, valid: bool):
    """Execute a fresh local engine. External policy label is set by the harness.

    A valid proposal is approved by the honest policy; a disallowed proposal
    is rejected by honest voters. Controlled voters approve either. The engine
    verifies votes, not the external policy. No real network or ECU is used.
    """
    if controlled_yes not in range(4) or type(valid) is not bool:
        raise ValueError("invalid experiment cell")
    ids = ["lab-v1", "lab-v2", "lab-v3"]
    keys = {identity: secrets.token_hex(32) for identity in ids}
    order = ids[:]
    random.Random(seed).shuffle(order)
    controlled = set(ids[:controlled_yes])
    engine = PermissionedConsensusEngine(keys, epoch=1)
    before = engine.metadata()
    # Constructed transport health wrapper; actual component metadata.
    # No native PQ handshake or enrollment enforcement is inferred from this.
    snapshot = {
        "connection_status": point("Connected"),
        "security_capability": point(security_capability_output(False)),
        "identity_security": point(identity_security_metadata()),
        "consensus_security": point(before),
    }
    posture_before = evaluate_security_strength(snapshot)["level"]
    proposal_id = "lab-policy-proposal"
    proposal_hash = hashlib.sha256(
        ("allowed" if valid else "disallowed").encode("ascii")
    ).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    transitions = []
    start = time.perf_counter_ns()
    for identity in order:
        vote = valid or identity in controlled
        signature = sign_vote(proposal_id, proposal_hash, identity, vote, 1, ts, keys[identity])
        result = engine.submit_vote(
            proposal_id=proposal_id, proposal_hash=proposal_hash,
            voter_id=identity, vote=vote, epoch=1,
            proposal_timestamp=ts, vote_signature=signature,
        )
        transitions.append({"voter": identity, "vote": vote, "status": result["status"],
                            "yes": result["yes_votes"], "no": result["no_votes"]})
        if result["status"] != "PENDING":
            break
    elapsed = time.perf_counter_ns() - start
    final = engine.tally(proposal_id)
    scope = new_scope()
    observation = observe_consensus(engine, proposal_id, scope)
    evidence = observation.export()
    snapshot["consensus_security"] = point(engine.metadata())
    posture_after = evaluate_security_strength(snapshot)["level"]
    gate = {claim: evaluate_claim(claim, posture_after, observation, expected_scope=scope,
                                 now_ns=time.monotonic_ns()).export()
            for claim in ("recorded_quorum_acceptance", "honest_validator_quorum", "external_policy_validity")}
    # The experimental policy label is not fed to the classifier.
    return {"seed": seed, "controlled_voters": controlled_yes,
            "policy_allows_proposal": valid, "quorum_threshold": final["quorum_threshold"],
            "arrival_order": order, "transitions": transitions,
            "final_status": final["status"], "posture_before": posture_before,
            "posture_after": posture_after,
            "unsupported_policy_acceptance": not valid and final["status"] == "ACCEPTED",
            "runtime_evidence": evidence, "expected_scope": scope,
            "declared_membership": before["validator_membership_enforced"],
            "declared_signature_required": before["vote_signature_required"],
            "declared_quorum_basis": before["quorum_basis"],
            "claim_gate": gate, "elapsed_ns": elapsed}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_campaign(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    rows = [trial(seed, controlled, valid) for seed in SEEDS
            for controlled in range(4) for valid in (False, True)]
    trace = out / "traces.jsonl"
    trace.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                     encoding="utf-8")
    fields = ("seed", "controlled_voters", "policy_allows_proposal", "quorum_threshold",
              "final_status", "posture_before", "posture_after",
              "unsupported_policy_acceptance", "elapsed_ns")
    csv_path = out / "decisions.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    cells = []
    for controlled in range(4):
        for valid in (False, True):
            group = [x for x in rows if x["controlled_voters"] == controlled
                     and x["policy_allows_proposal"] is valid]
            cells.append({"controlled_voters": controlled, "policy_allows_proposal": valid,
                          "runs": len(group),
                          "accepted": sum(x["final_status"] == "ACCEPTED" for x in group),
                          "strong_after": sum(x["posture_after"] == "STRONG" for x in group),
                          "unsupported_policy_acceptances": sum(x["unsupported_policy_acceptance"] for x in group),
                          "quorum_claim_eligible": sum(x["claim_gate"]["recorded_quorum_acceptance"]["eligibility"] == "ELIGIBLE" for x in group),
                          "policy_claim_withheld": sum(x["claim_gate"]["external_policy_validity"]["eligibility"] == "WITHHELD" for x in group)})
    summary = out / "summary.json"
    summary.write_text(json.dumps({"rows": len(rows), "cells": cells,
                                    "exploratory_only": True, "statistical_inference": False},
                                   indent=2) + "\n", encoding="utf-8")
    sources = ("permissioned_consensus.py", "runtime_security_strength.py",
               "security_capabilities.py", "identity_security.py", "release_metadata.py",
               "VERSION", "experiments/claim_validation/consensus_probe.py",
               "experiments/claim_validation/runtime_evidence.py", "experiments/claim_validation/claim_gate.py")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = {"schema": "claim-validity-consensus-pilot/1", "baseline_sha": BASELINE_SHA,
                "executed_sha": revision, "python": sys.version, "platform": platform.platform(),
                "seeds": list(SEEDS), "created_utc": datetime.now(timezone.utc).isoformat(),
                "source_sha256": {name: sha256(ROOT / name) for name in sources},
                "artifact_sha256": {p.name: sha256(p) for p in (trace, csv_path, summary)},
                "scope": "actual local consensus engine, constructed dashboard snapshot, synthetic policy labels",
                "native_pqc_executed": False, "real_network_executed": False,
                "publication_ready": False}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"rows": len(rows), "cells": cells}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    write_campaign(parser.parse_args().out)
