"""Assemble a scoped, same-run reproducibility archive for author review.

No publication/upload to DOI services. No git history, private correspondence,
environment variables, application logs, native binaries or secret files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = (
    "claim-validity-consensus-pilot", "claim-validity-identity-pilot",
    "claim-validity-pqc-pilot", "claim-validity-paired-consensus-identity",
    "claim-validity-paired-pqc", "claim-validity-design-consensus-identity",
    "claim-validity-design-pqc", "claim-validity-performance-consensus-identity",
    "claim-validity-performance-pqc", "claim-validity-heldout-consensus-identity",
    "claim-validity-heldout-pqc", "claim-validity-publication-evidence",
    "claim-validity-environment-local", "claim-validity-environment-pqc",
    "claim-validity-environment-audit",
)
ROOT_FILES = (
    "LICENSE", "VERSION", "permissioned_consensus.py", "runtime_security_strength.py",
    "security_capabilities.py", "identity_security.py", "consensus_security.py",
    "release_metadata.py", "sync_protocol.py", "sync_protocol_legacy.py",
    "runtime_security_monitor.py", "replay_security.py", "env_config.py",
    "credential_policy.py", "key_provider.py", "zkp_privacy.py",
    "v2x_protocol.py", "v2x_evidence_admission.py",
    "experiments/__init__.py", ".github/workflows/research-evidence.yml",
    "paper/claim-validity-heldout-protocol.md",
    "paper/claim-validity-related-work.md",
    "paper/claim-validity-reproduction.md",
)
# Explicit data formats; do not copy arbitrary runner output or logs.
DATA_NAMES = {"manifest.json", "summary.json", "traces.jsonl", "trials.jsonl",
              "decisions.csv", "paired_decisions.csv", "reference_checks.csv",
              "paired_design_decisions.csv", "observer_sensitivity.csv",
              "freshness.csv", "timing_blocks.csv", "audit.json",
              "heldout-eligibility.csv", "heldout-eligibility.svg",
              "heldout-eligibility.png", "environment.json", "pip-freeze.txt"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(cond, message):
    if not cond:
        raise ValueError(message)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def files_under(folder):
    return sorted(p for p in folder.rglob("*") if p.is_file())


def write_environment(out):
    out.mkdir(parents=True, exist_ok=False)
    freeze = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True)
    (out/"pip-freeze.txt").write_text(freeze, encoding="utf-8")
    info = {"executed_sha": git("rev-parse", "HEAD").decode().strip(),
            "python": sys.version, "platform": platform.platform(),
            "machine": platform.machine(), "cpu_count": os.cpu_count(),
            "runner_os": os.environ.get("RUNNER_OS"),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
            "pip_freeze_sha256": sha(out/"pip-freeze.txt")}
    provider = Path(os.environ.get("RUNNER_TEMP", "/nonexistent"))/"liboqs-source"
    if provider.is_dir():
        info["liboqs_commit"] = subprocess.check_output(
            ["git", "-C", str(provider), "rev-parse", "HEAD"], text=True).strip()
    (out/"environment.json").write_text(json.dumps(info, indent=2)+"\n", encoding="utf-8")


def validate_inputs(inputs, revision):
    require({p.name for p in inputs.iterdir() if p.is_dir()} == set(ARTIFACTS),
            "missing or unexpected artifact group")
    checked = 0
    for name in ARTIFACTS:
        folder = inputs/name
        files = files_under(folder)
        require(files and all(p.name in DATA_NAMES and not p.is_symlink() for p in files),
                "unexpected artifact content: " + name)
        for path in files:
            if path.suffix != ".json":
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            if "executed_sha" in data:
                require(data["executed_sha"] == revision, "mixed run revision: " + str(path))
                checked += 1
            for key in ("artifact_sha256", "outputs_sha256"):
                for filename, expected in data.get(key, {}).items():
                    require(Path(filename).name == filename and sha(path.parent/filename) == expected,
                            "artifact digest mismatch: " + filename)
            for filename, field in (("trials.jsonl", "trace_sha256"),
                                    ("paired_decisions.csv", "paired_csv_sha256"),
                                    ("pip-freeze.txt", "pip_freeze_sha256")):
                if field in data and (path.parent/filename).is_file():
                    require(sha(path.parent/filename) == data[field], "digest mismatch: " + filename)
    audit = json.loads((inputs/"claim-validity-publication-evidence"/"audit.json").read_text())
    require(audit["verified_trials"] == 82 and audit["executed_sha"] == revision,
            "publication audit incomplete")
    heldout = {}
    for name in ("claim-validity-heldout-consensus-identity", "claim-validity-heldout-pqc"):
        for path in (inputs/name).rglob("summary.json"):
            data = json.loads(path.read_text())
            require(data["domain"] not in heldout, "duplicate held-out domain")
            heldout[data["domain"]] = {"summary.json": sha(path), "trials.jsonl": sha(path.parent/"trials.jsonl")}
    require(heldout == audit["artifact_input_sha256"], "audit input hashes do not match packaged traces")
    require(checked >= 15, "incomplete provenance")
    return checked


def assemble(inputs, out):
    revision = git("rev-parse", "HEAD").decode().strip()
    checked = validate_inputs(inputs, revision)
    out.mkdir(parents=True, exist_ok=False)
    stage = out/"staging"
    source = stage/"source"
    tracked = git("ls-tree", "-r", "--name-only", "HEAD").decode().splitlines()
    selected = sorted(set(ROOT_FILES) | {p for p in tracked if
                      (p.startswith("experiments/claim_validation/") and Path(p).suffix in {".py", ".json"})
                      or (p.startswith("tests/test_claim_validation_") and p.endswith(".py"))})
    for name in selected:
        require(name in tracked, "missing source: " + name)
        target = source/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git("show", "HEAD:" + name))
    shutil.copytree(inputs, stage/"evidence")
    shutil.copyfile(source/"paper/claim-validity-reproduction.md", stage/"README.md")
    report = {"schema": "claim-validity-reproducibility/1",
              "executed_sha": revision, "git_tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
              "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
              "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "source_scope": "allowlisted experiment source subset from exact executed tree",
              "verified_revision_records": checked, "artifact_groups": list(ARTIFACTS),
              "files_sha256": {p.relative_to(stage).as_posix(): sha(p) for p in files_under(stage)},
              "doi": None, "publication_status": "author review required"}
    (stage/"MANIFEST.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    archive = out/"claim-validity-reproducibility.zip"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED, compresslevel=6) as z:
        for path in files_under(stage):
            z.write(path, path.relative_to(stage).as_posix())
    with ZipFile(archive) as z:
        require(z.testzip() is None, "ZIP integrity failure")
        for name, expected in report["files_sha256"].items():
            require(hashlib.sha256(z.read(name)).hexdigest() == expected, "ZIP member digest mismatch")
    (out/"archive.sha256").write_text(sha(archive)+"  "+archive.name+"\n", encoding="utf-8")
    shutil.copyfile(stage/"MANIFEST.json", out/"MANIFEST.json")
    shutil.rmtree(stage)
    print(json.dumps({"executed_sha": revision, "artifact_groups": len(ARTIFACTS),
                      "source_files": len(selected), "packaged_files": len(report["files_sha256"]),
                      "archive_sha256": sha(archive), "doi": None}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.environment:
        write_environment(args.environment)
    elif args.input and args.out:
        assemble(args.input, args.out)
    else:
        parser.error("provide --environment or --input and --out")
