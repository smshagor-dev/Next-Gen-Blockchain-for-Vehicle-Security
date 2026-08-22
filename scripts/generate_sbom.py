#!/usr/bin/env python3
"""Generate a compact deterministic CycloneDX-style SBOM for OmniGuard V2X.

This records dependencies that are actually pinned/declared in the repository.
It does not claim transitive completeness for system packages installed outside
this source tree.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
CMAKE = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
GO_MOD = (ROOT / "api/go/go.mod").read_text(encoding="utf-8")


def match(pattern: str, text: str, label: str) -> str:
    found = re.search(pattern, text, flags=re.MULTILINE)
    if not found:
        raise RuntimeError(f"could not resolve {label}")
    return found.group(1)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_sbom() -> dict:
    liboqs_version = match(r'SMARTCAR_LIBOQS_VERSION "([^"]+)"', CMAKE, "liboqs version")
    liboqs_commit = match(r'SMARTCAR_LIBOQS_COMMIT "([0-9a-f]{40})"', CMAKE, "liboqs commit")
    json_version = match(r"nlohmann/json/releases/download/v([^/]+)/", CMAKE, "nlohmann/json version")
    json_sha = match(r"URL_HASH SHA256=([0-9a-f]{64})", CMAKE, "nlohmann/json checksum")
    go_version = match(r"^go\s+([^\s]+)$", GO_MOD, "Go module version")

    components = [
        {
            "type": "library",
            "name": "liboqs",
            "version": liboqs_version,
            "purl": f"pkg:github/open-quantum-safe/liboqs@{liboqs_commit}",
            "properties": [{"name": "omniguard:pinned_commit", "value": liboqs_commit}],
        },
        {
            "type": "library",
            "name": "nlohmann-json",
            "version": json_version,
            "purl": f"pkg:github/nlohmann/json@v{json_version}",
            "hashes": [{"alg": "SHA-256", "content": json_sha}],
        },
        {
            "type": "framework",
            "name": "Go toolchain module language",
            "version": go_version,
            "properties": [{"name": "omniguard:source", "value": "api/go/go.mod"}],
        },
        {
            "type": "library",
            "name": "OpenSSL Crypto",
            "version": ">=3.0",
            "properties": [{"name": "omniguard:resolution", "value": "system/build-environment"}],
        },
    ]
    components.sort(key=lambda item: (item["name"], item["version"]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:omniguard-v2x-{VERSION}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "OmniGuard V2X",
                "version": VERSION,
            },
            "properties": [
                {"name": "omniguard:scope", "value": "repository-declared direct build dependencies"},
                {"name": "omniguard:transitive_system_packages_complete", "value": "false"},
                {"name": "omniguard:secret_values_exposed", "value": "false"},
            ],
        },
        "components": components,
        "source_hashes": {
            "CMakeLists.txt": sha256_file(ROOT / "CMakeLists.txt"),
            "api/go/go.mod": sha256_file(ROOT / "api/go/go.mod"),
        },
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="security-reports/sbom-v3.0.3.cdx.json")
    args = parser.parse_args()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_sbom(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"SBOM generated: {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
