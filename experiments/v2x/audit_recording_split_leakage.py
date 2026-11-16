"""Fail-closed independent recording-group leakage audit for V2X/CAN trial manifests.

This checks experimental split hygiene, not model efficacy or source authenticity.
Input JSON: {"trials":[{"trial_id":"...", "split":"train|validation|test",
"source_sha256":"64 hex", "recording_group":"...", "incident_id":"..."}]}.
"""
import argparse
import hashlib
import json
from pathlib import Path

SPLITS = {"train", "validation", "test"}
FIELDS = {"trial_id", "split", "source_sha256", "recording_group", "incident_id"}

def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result

def audit(raw: bytes) -> dict:
    doc = json.loads(raw, object_pairs_hook=_no_duplicates)
    if not isinstance(doc, dict) or set(doc) != {"trials"} or not isinstance(doc["trials"], list) or not doc["trials"]:
        raise ValueError("nonempty trials array required")
    trial_ids, incident_ids, group_splits, source_splits = set(), set(), {}, {}
    counts = {split: 0 for split in sorted(SPLITS)}
    for trial in doc["trials"]:
        if not isinstance(trial, dict) or set(trial) != FIELDS:
            raise ValueError("invalid trial schema")
        if any(not isinstance(trial[k], str) or not trial[k] or trial[k] != trial[k].strip() for k in FIELDS):
            raise ValueError("invalid trial field")
        if trial["split"] not in SPLITS:
            raise ValueError("invalid split")
        digest = trial["source_sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid lowercase source digest")
        if trial["trial_id"] in trial_ids or trial["incident_id"] in incident_ids:
            raise ValueError("duplicate trial or incident ID")
        trial_ids.add(trial["trial_id"])
        incident_ids.add(trial["incident_id"])
        group = (digest, trial["recording_group"])
        for index, key in ((group_splits, group), (source_splits, digest)):
            if key in index and index[key] != trial["split"]:
                raise ValueError("cross-split recording/source leakage")
            index[key] = trial["split"]
        counts[trial["split"]] += 1
    return {"input_sha256": hashlib.sha256(raw).hexdigest(), "trial_count": len(trial_ids),
            "recording_groups": len(group_splits), "source_files": len(source_splits),
            "split_counts": counts, "status": "split_integrity_only"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.expected_sha256:
        raise SystemExit("manifest digest mismatch")
    print(json.dumps(audit(raw), sort_keys=True))

if __name__ == "__main__":
    main()
