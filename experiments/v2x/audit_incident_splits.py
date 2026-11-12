"""Structural audit of independently annotated incident-level split manifests.

Never infer incident truth from a CAM attacker flag or self-reported evidence.
"""
import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

REQUIRED = ("source_id", "incident_id", "group_id", "split", "label", "label_provenance")
SPLITS = {"train", "validation", "test"}
LABELS = {"0", "1"}
UNSUPPORTED = {"attacker", "cam_attacker", "self_reported", "unknown", "synthetic"}


def audit(path: Path) -> dict:
    raw = path.read_bytes()
    rows = list(csv.DictReader(raw.decode("utf-8-sig").splitlines()))
    if not rows:
        raise ValueError("empty manifest")
    if not set(REQUIRED).issubset(rows[0]):
        raise ValueError("missing required columns")
    groups = {}
    seen = set()
    counts = Counter()
    for index, row in enumerate(rows, 2):
        if any(not row.get(field, "").strip() for field in REQUIRED):
            raise ValueError(f"row {index}: empty required field")
        split, label = row["split"].strip(), row["label"].strip()
        if split not in SPLITS or label not in LABELS:
            raise ValueError(f"row {index}: invalid split or binary label")
        if row["label_provenance"].strip().lower() in UNSUPPORTED:
            raise ValueError(f"row {index}: unsupported incident ground truth provenance")
        key = (row["source_id"], row["incident_id"])
        if key in seen:
            raise ValueError(f"row {index}: duplicate source/incident")
        seen.add(key)
        group = (row["source_id"], row["group_id"])
        if group in groups and groups[group] != split:
            raise ValueError(f"row {index}: group leakage across splits")
        groups[group] = split
        counts[(split, label)] += 1
    return {
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "rows": len(rows),
        "unique_groups": len(groups),
        "split_label_counts": {f"{s}:{l}": counts[(s, l)] for s in sorted(SPLITS) for l in sorted(LABELS)},
        "status": "structural_audit_only",
        "independent_ground_truth_verified": False,
        "publication_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(audit(args.manifest), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
