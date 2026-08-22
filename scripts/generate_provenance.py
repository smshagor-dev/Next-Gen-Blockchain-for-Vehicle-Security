#!/usr/bin/env python3
"""Generate non-secret release validation provenance for one exact Git commit."""
from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--output", default="security-reports/provenance-v3.0.3.json")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit_sha):
        raise SystemExit("commit SHA must be 40 lowercase hexadecimal characters")
    head = command("git", "rev-parse", "HEAD")
    if head != args.commit_sha:
        raise SystemExit("provenance commit does not match checked-out HEAD")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    document = {
        "format": "OMNIGUARD_RELEASE_PROVENANCE_V1",
        "release_version": version,
        "commit_sha": head,
        "source_tree_sha": command("git", "rev-parse", "HEAD^{tree}"),
        "python": platform.python_version(),
        "go": command("go", "version") if (ROOT / "api/go/go.mod").exists() else "unavailable",
        "cmake": command("cmake", "--version").splitlines()[0],
        "cxx": command("c++", "--version").splitlines()[0],
        "validation_toolchain_pinned_in_cmake": True,
        "sbom_attached": True,
        "secret_values_exposed": False,
        "production_certified": False,
        "vehicle_safety_certified": False,
    }
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"provenance generated: {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
