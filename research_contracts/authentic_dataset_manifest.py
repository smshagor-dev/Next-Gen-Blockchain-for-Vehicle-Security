"""Fail-closed local provenance verifier. Does not certify dataset authenticity."""
import argparse
import hashlib
import json
from pathlib import Path

SUPPORTED = {"veremi-nextgen", "can-intrusion", "other-can"}


def verify_manifest(root, manifest):
    root = Path(root).resolve(strict=True)
    if not isinstance(manifest, dict) or set(manifest) != {"dataset", "source_url", "license", "acquired_utc", "files"}:
        raise ValueError("invalid manifest fields")
    if manifest["dataset"] not in SUPPORTED:
        raise ValueError("unsupported dataset family")
    for field in ("source_url", "license", "acquired_utc"):
        if not isinstance(manifest[field], str) or not manifest[field].strip():
            raise ValueError("missing " + field)
    if not manifest["source_url"].startswith("https://"):
        raise ValueError("source_url must be HTTPS")
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise ValueError("at least one file required")
    seen = set()
    verified = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes", "role"}:
            raise ValueError("invalid file record")
        relative = item["path"]
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise ValueError("invalid relative path")
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("path escapes dataset root")
        if relative in seen:
            raise ValueError("duplicate file")
        seen.add(relative)
        if item["role"] not in ("raw", "labels", "metadata"):
            raise ValueError("invalid role")
        if type(item["bytes"]) is not int or item["bytes"] < 0:
            raise ValueError("invalid byte count")
        digest = item["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid digest")
        h = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1048576), b""):
                h.update(chunk)
                size += len(chunk)
        if size != item["bytes"] or h.hexdigest() != digest:
            raise ValueError("content mismatch: " + relative)
        verified.append({"path": relative, "sha256": digest, "bytes": size, "role": item["role"]})
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return {"dataset": manifest["dataset"], "verified_files": verified,
            "manifest_sha256": hashlib.sha256(canonical).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    with open(args.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    print(json.dumps(verify_manifest(args.root, manifest), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
