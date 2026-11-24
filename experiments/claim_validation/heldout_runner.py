"""Execute a precommitted finite held-out schedule in fresh subprocesses."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEDULE = "experiments/claim_validation/heldout_schedule.json"
FROZEN = {
    SCHEDULE: "71e8ef83e27463c0940f9e7698b5d522d8622cb5",
    "experiments/claim_validation/claim_gate.py": "03690ef3b39812772907d6b478bde2529c171d1c",
    "experiments/claim_validation/runtime_evidence.py": "067efea791d886b4619be4eb8f24eb0e7fbdd666",
}
SCHEDULE_COMMIT = "93c5a6f03cac21076041767efbda58b5dfaf6ccd"
CANDIDATE = "5a5e0851496f31e4afd626aeee218b0aeab66cb5"
COUNTS = {"consensus": 48, "identity": 24, "pqc": 10}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_schedule():
    for path, expected in FROZEN.items():
        actual = subprocess.check_output(["git", "hash-object", path], cwd=ROOT, text=True).strip()
        if actual != expected:
            raise RuntimeError("frozen blob mismatch: " + path)
    schedule = json.loads((ROOT / SCHEDULE).read_text(encoding="utf-8"))
    cases = schedule["cases"]
    if (schedule["schema"] != "heldout-claim-validation/1" or schedule["candidate"] != CANDIDATE
            or len({c["id"] for c in cases}) != len(cases)
            or Counter(c["domain"] for c in cases) != COUNTS):
        raise ValueError("schedule does not match frozen design")
    return cases


def worker_input(case):
    return {k:v for k,v in case.items() if not k.startswith("expected")}


def adjudicate(case, direct):
    domain = case["domain"]
    if domain == "consensus":
        q = (case["n"] * case["num"] + case["den"] - 1) // case["den"]
        return (direct["threshold"] == q and direct["status"] == case["expected_status"]
                and direct["error"] == case["expected_error"]
                and (direct["status"] == "ACCEPTED") is case["expected"])
    if domain == "identity":
        return (direct["ack"] is case["expected_ack"] and direct["bound"] is case["expected_ack"]
                and direct["registry_size"] == case["size"]
                and (direct["ack"] and direct["registry_member"]) is case["expected"])
    if domain == "pqc":
        return (direct["matched"] is case["expected_matched"] and direct["mode"] == case["expected_mode"]
                and (direct["matched"] and direct["client_mode"] == "PQC_KEM"
                     and direct["negotiated_kem"] == "ML-KEM-512") is case["expected"])
    raise ValueError("unknown domain")


def run_case(case):
    base = {"id": case["id"], "domain": case["domain"], "cell": case["cell"],
            "replicate": case["replicate"], "reference_supported": case["expected"]}
    # Limit inherited application configuration; retain PATH and provider library paths.
    env = {k:v for k,v in os.environ.items() if not k.startswith("SMARTCAR_")}
    try:
        result = subprocess.run([sys.executable, "-m", "experiments.claim_validation.heldout_worker"],
                                input=json.dumps(worker_input(case)), text=True, capture_output=True,
                                timeout=30, cwd=ROOT, env=env)
        if result.returncode:
            return {**base, "status": "worker_error", "returncode": result.returncode,
                    "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest()}
        marker = [line for line in result.stdout.splitlines() if line.startswith("HELDOUT_RESULT=")]
        if len(marker) != 1:
            return {**base, "status": "invalid_worker_output"}
        output = json.loads(marker[0].split("=",1)[1])
        agrees = adjudicate(case, output["direct"])
        return {**base, "status": "ok" if agrees else "reference_disagreement", "output": output}
    except subprocess.TimeoutExpired:
        return {**base, "status": "timeout"}
    except Exception as exc:
        return {**base, "status": "runner_error", "error_type": type(exc).__name__}


def summarize(rows):
    cells = {}
    for row in rows:
        cells.setdefault(row["cell"], []).append(row)
    report = []
    for cell, group in sorted(cells.items()):
        ok = [r for r in group if r["status"] == "ok"]
        methods = {}
        for name in ("posture_proxy", "declared_proxy", "gate"):
            def eligible(row):
                value = row["output"][name]
                return value["eligibility"] == "ELIGIBLE" if name == "gate" else value is True
            methods[name] = {"supported_eligible": sum(r["reference_supported"] and eligible(r) for r in ok),
                             "unsupported_eligible": sum(not r["reference_supported"] and eligible(r) for r in ok)}
        report.append({"cell": cell, "scheduled": len(group), "evaluated": len(ok),
                       "errors": len(group)-len(ok),
                       "positive": sum(r["reference_supported"] for r in ok),
                       "negative": sum(not r["reference_supported"] for r in ok), "methods": methods,
                       "gate_withheld": sum(r["output"]["gate"]["eligibility"] == "WITHHELD" for r in ok),
                       "gate_not_supported": sum(r["output"]["gate"]["eligibility"] == "NOT_SUPPORTED" for r in ok)})
    return report


def run(domain, out):
    cases = [c for c in load_schedule() if c["domain"] == domain]
    out.mkdir(parents=True, exist_ok=False)
    trace = out / "trials.jsonl"
    rows = []
    with trace.open("w", encoding="utf-8") as f:
        for case in cases:
            row = run_case(case)
            rows.append(row)
            f.write(json.dumps(row, sort_keys=True) + "\n")
            f.flush()
    report = {"domain": domain, "scheduled": len(cases),
              "statuses": dict(Counter(r["status"] for r in rows)),
              "cells": summarize(rows), "executed_sha": subprocess.check_output(["git","rev-parse","HEAD"], cwd=ROOT, text=True).strip(),
              "schedule_commit": SCHEDULE_COMMIT, "candidate_commit": CANDIDATE,
              "schedule_sha256": digest(ROOT / SCHEDULE), "frozen_git_blobs": FROZEN,
              "runner_sha256": digest(Path(__file__)), "worker_sha256": digest(Path(__file__).with_name("heldout_worker.py")),
              "python": sys.version, "platform": platform.platform(), "trace_sha256": digest(trace),
              "statistical_inference": False, "scope": "new fixed-design cells, one local subprocess per trial"}
    (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if any(r["status"] != "ok" for r in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", choices=COUNTS, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.domain, args.out)
