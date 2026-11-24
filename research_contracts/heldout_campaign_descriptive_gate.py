"""Descriptive, non-actuating held-out V2X campaign comparison. No significance claim."""
import csv
import hashlib
from collections import defaultdict

def evaluate(csv_path, expected_sha256):
    raw = open(csv_path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if len(expected_sha256) != 64 or digest != expected_sha256.lower():
        raise ValueError("recording digest mismatch")
    rows = list(csv.DictReader(raw.decode("utf-8-sig").splitlines()))
    required = {"campaign_id", "incident_id", "split", "label", "baseline_score", "candidate_score"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError("empty recording or missing columns")
    seen, splits, heldout = set(), {}, defaultdict(list)
    for row in rows:
        campaign, incident, split = (row[k].strip() for k in ("campaign_id", "incident_id", "split"))
        if not campaign or not incident or split not in ("train", "validation", "test"):
            raise ValueError("invalid identifiers or split")
        if (campaign, incident) in seen:
            raise ValueError("duplicate incident")
        seen.add((campaign, incident))
        if campaign in splits and splits[campaign] != split:
            raise ValueError("campaign split leakage")
        splits[campaign] = split
        if any(row[k] not in ("0", "1") for k in ("label", "baseline_score", "candidate_score")):
            raise ValueError("nonbinary label or decision")
        if split == "test":
            heldout[campaign].append(tuple(int(row[k]) for k in ("label", "baseline_score", "candidate_score")))
    if not heldout:
        raise ValueError("no test campaigns")
    def balanced_accuracy(records, index):
        classes = [[int(r[index] == label) for r in records if r[0] == label] for label in (0, 1)]
        return sum(sum(v)/len(v) for v in classes)/2 if all(classes) else None
    results = []
    for campaign, records in sorted(heldout.items()):
        base, candidate = balanced_accuracy(records, 1), balanced_accuracy(records, 2)
        results.append({"campaign_id": campaign, "incidents": len(records),
                        "baseline_balanced_accuracy": base, "candidate_balanced_accuracy": candidate,
                        "paired_difference": candidate-base if base is not None else None})
    differences = [r["paired_difference"] for r in results if r["paired_difference"] is not None]
    return {"source_sha256": digest, "inference": "descriptive_only", "test_campaigns": len(results),
            "evaluable_campaigns": len(differences),
            "campaign_equal_mean_difference": sum(differences)/len(differences) if differences else None,
            "results": results}
