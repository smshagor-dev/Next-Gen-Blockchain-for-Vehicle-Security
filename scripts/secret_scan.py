#!/usr/bin/env python3
"""Fail-closed scan for prohibited tracked secret material.

This intentionally scans the current tracked source tree only. Historical Git
remediation is a separate owner-controlled operation documented in the release
runbook; this tool never prints suspected secret values.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_ENV = {".env.example"}
PROHIBITED_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
PROHIBITED_EXACT_LITERALS = {
    # Historical default known to have existed; do not print the literal itself.
    "legacy_poa_default": re.compile(r"DEFAULT_POA_AUTHORITY_KEY\s*=\s*['\"][^'\"]+['\"]"),
}
PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----")


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if raw:
            paths.append(ROOT / raw.decode("utf-8", errors="strict"))
    return paths


def main() -> None:
    findings: list[str] = []
    for path in tracked_files():
        rel = path.relative_to(ROOT).as_posix()
        name = path.name
        if name == ".env" or (name.startswith(".env.") and name not in ALLOWED_ENV):
            findings.append(f"prohibited tracked environment file: {rel}")
        if path.suffix.lower() in PROHIBITED_SUFFIXES:
            findings.append(f"prohibited tracked key/certificate container: {rel}")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if PRIVATE_KEY_MARKER.search(text):
            findings.append(f"private-key PEM marker found: {rel}")
        for label, pattern in PROHIBITED_EXACT_LITERALS.items():
            if pattern.search(text):
                findings.append(f"prohibited {label} declaration found: {rel}")

    if findings:
        for finding in sorted(set(findings)):
            print(f"SECRET-SCAN: {finding}")
        raise SystemExit(1)
    print("SECRET-SCAN: PASS (current tracked tree; no secret values emitted)")


if __name__ == "__main__":
    main()
