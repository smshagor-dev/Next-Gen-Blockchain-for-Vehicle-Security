"""Fail-closed recording provenance and campaign split gate (not evidence of efficacy)."""
import argparse
import hashlib
import json
from pathlib import Path

class ProvenanceError(ValueError):
    pass

def verify_manifest(manifest_path, root):
    root = Path(root).resolve()
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if type(manifest) is not dict or type(manifest.get("recordings")) is not list or not manifest["recordings"]:
        raise ProvenanceError("nonempty recordings list required")
    paths, hashes, groups, records = set(), {}, {}, []
    for item in manifest["recordings"]:
        if type(item) is not dict:
            raise ProvenanceError("recording must be an object")
        rel, digest, split, group, source = (item.get(k) for k in ("path", "sha256", "split", "campaign_id", "source"))
        if not all(type(v) is str and v for v in (rel, digest, split, group, source)):
            raise ProvenanceError("missing recording provenance field")
        if split not in ("train", "validation", "test"):
            raise ProvenanceError("unknown split")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ProvenanceError("invalid sha256")
        p = Path(rel)
        if p.is_absolute() or ".." in p.parts or rel in paths:
            raise ProvenanceError("unsafe or duplicate path")
        paths.add(rel)
        target = (root / p).resolve()
        if not target.is_relative_to(root) or not target.is_file() or (root / p).is_symlink():
            raise ProvenanceError("missing, escaped, or symlinked recording")
        with target.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != digest:
            raise ProvenanceError("recording digest mismatch")
        if digest in hashes and hashes[digest] != split:
            raise ProvenanceError("identical bytes across splits")
        hashes[digest] = split
        if group in groups and groups[group] != split:
            raise ProvenanceError("campaign leakage across splits")
        groups[group] = split
        records.append({"path": rel, "sha256": digest, "split": split, "campaign_id": group, "source": source})
    return {"verified_recordings": len(records), "campaigns": len(groups), "splits": sorted({x["split"] for x in records}), "records": records}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    print(json.dumps(verify_manifest(args.manifest, args.root), indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
