"""Deterministic release-integrity manifest generation for OmniGuard V2X.

The manifest records hashes and metadata only. It never embeds file contents,
environment values, credentials, or private key material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

from release_metadata import INTERNAL_HARDENING_PHASE, RELEASE_VERSION

MANIFEST_SCHEMA = "OMNIGUARD_RELEASE_INTEGRITY_V1"
RELEASE_TAG = f"v{RELEASE_VERSION}"
_FORBIDDEN_EXACT_PATHS = {".env"}
_FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def tracked_files(root: Path) -> List[str]:
    raw = _git(root, "ls-files", "-z")
    return sorted(item for item in raw.split("\0") if item)


def _assert_no_forbidden_tracked_material(paths: Iterable[str]) -> None:
    violations: List[str] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        name = Path(normalized).name.lower()
        if normalized in _FORBIDDEN_EXACT_PATHS:
            violations.append(normalized)
            continue
        if name.startswith(".env.") and name != ".env.example":
            violations.append(normalized)
            continue
        if Path(name).suffix.lower() in _FORBIDDEN_SUFFIXES:
            violations.append(normalized)
    if violations:
        raise RuntimeError(
            "release integrity gate rejected tracked sensitive material: "
            + ", ".join(sorted(violations))
        )


def _cmake_dependency_pins(root: Path) -> Dict[str, str]:
    text = (root / "CMakeLists.txt").read_text(encoding="utf-8")

    def required(pattern: str, label: str) -> str:
        match = re.search(pattern, text)
        if not match:
            raise RuntimeError(f"release integrity gate could not resolve {label}")
        return match.group(1)

    return {
        "liboqs_version": required(
            r'set\(SMARTCAR_LIBOQS_VERSION\s+"([^"]+)"\)', "liboqs version"
        ),
        "liboqs_commit": required(
            r'set\(SMARTCAR_LIBOQS_COMMIT\s+"([0-9a-f]{40})"\)', "liboqs commit"
        ),
        "nlohmann_json_version": required(
            r'nlohmann/json/releases/download/v([^/]+)/json\.tar\.xz',
            "nlohmann/json version",
        ),
        "nlohmann_json_sha256": required(
            r'URL_HASH\s+SHA256=([0-9a-f]{64})', "nlohmann/json SHA-256"
        ),
    }


def build_manifest(
    root: Path = Path("."),
    *,
    commit_sha: Optional[str] = None,
) -> Dict[str, object]:
    root = root.resolve()
    canonical = (root / "VERSION").read_text(encoding="utf-8").strip()
    if canonical != RELEASE_VERSION:
        raise RuntimeError(
            f"release version drift: VERSION={canonical!r}, metadata={RELEASE_VERSION!r}"
        )

    paths = tracked_files(root)
    _assert_no_forbidden_tracked_material(paths)

    files: List[Dict[str, object]] = []
    total_bytes = 0
    for relative in paths:
        path = root / relative
        if not path.is_file():
            raise RuntimeError(f"tracked release path is not a regular file: {relative}")
        size = path.stat().st_size
        total_bytes += size
        files.append(
            {
                "path": relative.replace("\\", "/"),
                "size": size,
                "sha256": _sha256_file(path),
            }
        )

    resolved_commit = str(commit_sha or _git(root, "rev-parse", "HEAD")).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", resolved_commit):
        raise RuntimeError("release commit SHA must be a 40-character hexadecimal value")

    return {
        "schema": MANIFEST_SCHEMA,
        "release_version": RELEASE_VERSION,
        "release_tag": RELEASE_TAG,
        "internal_hardening_phase": INTERNAL_HARDENING_PHASE,
        "commit_sha": resolved_commit.lower(),
        "source_tree": {
            "tracked_file_count": len(files),
            "tracked_total_bytes": total_bytes,
            "files": files,
        },
        "dependency_pins": _cmake_dependency_pins(root),
        "native_security_profile": {
            "data_protection": "AES-256-GCM",
            "signature": "ML-DSA-44",
            "key_encapsulation": "ML-KEM-512",
            "simulated_pqc_supported_target": False,
            "legacy_demo_isolated": True,
        },
        "claims": {
            "production_certified": False,
            "vehicle_safety_certified": False,
            "formal_verification_complete": False,
        },
        "secret_values_exposed": False,
    }


def write_manifest(
    output: Path,
    *,
    root: Path = Path("."),
    commit_sha: Optional[str] = None,
) -> Dict[str, object]:
    manifest = build_manifest(root, commit_sha=commit_sha)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify_manifest(path: Path, *, root: Path = Path(".")) -> bool:
    received = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(received, Mapping):
        return False
    commit_sha = str(received.get("commit_sha", ""))
    expected = build_manifest(root, commit_sha=commit_sha)
    return received == expected


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate/verify the v3.0.2 integrity manifest")
    parser.add_argument("--output", type=Path, default=Path("security-reports/release-integrity-manifest.json"))
    parser.add_argument("--commit-sha", default=None)
    parser.add_argument("--verify", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.verify is not None:
        if not verify_manifest(args.verify):
            print("release integrity verification: FAILED")
            return 1
        print("release integrity verification: PASS")
        return 0

    manifest = write_manifest(args.output, commit_sha=args.commit_sha)
    print(
        "release integrity manifest: PASS "
        f"version={manifest['release_version']} "
        f"files={manifest['source_tree']['tracked_file_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
