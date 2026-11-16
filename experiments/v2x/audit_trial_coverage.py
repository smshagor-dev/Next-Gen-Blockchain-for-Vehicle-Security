"""Fail-closed paired incident universe audit. Missing predictions are no-alert, not excluded."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

class CoverageError(ValueError):
    pass

def read_rows(path, expected):
    raw = Path(path).read_bytes()
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")), strict=True)
        if reader.fieldnames != expected:
            raise CoverageError("Unexpected CSV columns")
        rows = []
        for row in reader:
            if None in row or any(v is None or not v or v.strip() != v for v in row.values()):
                raise CoverageError("Ragged, empty or padded CSV field")
            rows.append(row)
    except (UnicodeError, csv.Error) as exc:
        raise CoverageError("Malformed CSV") from exc
    return rows, hashlib.sha256(raw).hexdigest()

def audit(world_file, candidate_file, baseline_file):
    world, world_hash = read_rows(world_file, ["incident_id", "cluster_id", "truth"])
    if not world:
        raise CoverageError("Empty incident universe")
    universe = {}
    for row in world:
        ident = row["incident_id"]
        if ident in universe or row["truth"] not in ("0", "1"):
            raise CoverageError("Duplicate incident or invalid truth")
        universe[ident] = row
    methods = {}
    observed = {}
    for name, path in (("candidate", candidate_file), ("baseline", baseline_file)):
        rows, digest = read_rows(path, ["incident_id", "alert"])
        predictions = {}
        for row in rows:
            ident = row["incident_id"]
            if ident not in universe or ident in predictions or row["alert"] not in ("0", "1"):
                raise CoverageError("Unknown/duplicate incident or invalid alert")
            predictions[ident] = int(row["alert"])
        observed[name] = predictions
        counts = dict(tp=0, fp=0, tn=0, fn=0)
        for ident, row in universe.items():
            truth = int(row["truth"])
            alert = predictions.get(ident, 0)
            key = ("tp" if alert else "fn") if truth else ("fp" if alert else "tn")
            counts[key] += 1
        methods[name] = {"sha256": digest, "observed": len(predictions),
                         "missing_scored_as_no_alert": len(universe) - len(predictions),
                         "confusion": counts}
    # Pair on the entire externally supplied incident universe, never only detections.
    paired = dict(both_correct=0, candidate_only_correct=0,
                  baseline_only_correct=0, both_wrong=0)
    coverage = dict(both_observed=0, candidate_only_observed=0,
                    baseline_only_observed=0, neither_observed=0)
    for ident, row in universe.items():
        truth = int(row["truth"])
        cp, bp = observed["candidate"], observed["baseline"]
        cc, bc = cp.get(ident, 0) == truth, bp.get(ident, 0) == truth
        pair_key = ("both_correct" if bc else "candidate_only_correct") if cc else ("baseline_only_correct" if bc else "both_wrong")
        paired[pair_key] += 1
        co, bo = ident in cp, ident in bp
        coverage[("both_observed" if bo else "candidate_only_observed") if co else ("baseline_only_observed" if bo else "neither_observed")] += 1
    return {"protocol": "paired-world-coverage-v2", "world_sha256": world_hash,
            "world_incidents": len(universe),
            "clusters": len({r["cluster_id"] for r in world}),
            "methods": methods, "paired_correctness": paired,
            "coverage_asymmetry": coverage,
            "limitation": "Operator-supplied hashes do not establish independent truth or publisher authenticity"}

def main():
    p = argparse.ArgumentParser()
    for arg in ("world", "candidate", "baseline", "output"):
        p.add_argument("--" + arg, required=True)
    a = p.parse_args()
    result = audit(a.world, a.candidate, a.baseline)
    Path(a.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
