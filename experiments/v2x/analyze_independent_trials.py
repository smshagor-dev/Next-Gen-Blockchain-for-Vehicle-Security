"""Cluster-aware analysis of independently collected paired V2X trial outcomes.

Inputs are independent *trial-level* summaries from a separate capture/label
pipeline. This module cannot establish independence, ground-truth authenticity,
or executed policy provenance. Never treat synthetic tests as paper results.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from pathlib import Path

MAX_TRIALS = 10000
FIELDS = {"trial_id", "independent_cluster_id", "scenario_id", "split",
          "source_sha256", "baseline", "candidate"}
COUNTS = {"tp", "fp", "tn", "fn"}


def parse_trials(data: bytes) -> list[dict]:
    if not isinstance(data, bytes) or len(data) > 8 * 1024 * 1024:
        raise ValueError("trial summaries exceed 8 MiB")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ValueError("invalid UTF-8") from exc
    if not lines or len(lines) > MAX_TRIALS or any(not line.strip() for line in lines):
        raise ValueError("expected 1..10000 nonempty trial lines")
    records, ids, clusters, sources = [], set(), set(), set()
    def unique_pairs(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError("duplicate JSON key")
            obj[k] = v
        return obj
    for line in lines:
        try:
            r = json.loads(line, object_pairs_hook=unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSONL trial") from exc
        if not isinstance(r, dict) or set(r) != FIELDS:
            raise ValueError("trial summary schema mismatch")
        for name in ("trial_id", "independent_cluster_id", "scenario_id", "split"):
            if not isinstance(r[name], str) or not r[name].strip() or len(r[name]) > 256:
                raise ValueError("invalid trial identifier")
        if r["split"] != "test":
            raise ValueError("analysis accepts held-out test split only")
        if not isinstance(r["source_sha256"], str) or len(r["source_sha256"]) != 64 or any(
                c not in "0123456789abcdef" for c in r["source_sha256"]):
            raise ValueError("invalid source digest")
        for name, values, used in (("trial_id", r["trial_id"], ids),
                                   ("independent_cluster_id", r["independent_cluster_id"], clusters),
                                   ("source_sha256", r["source_sha256"], sources)):
            if values in used:
                raise ValueError("duplicate " + name + "; cluster independence is not established")
            used.add(values)
        for arm in ("baseline", "candidate"):
            counts = r[arm]
            if not isinstance(counts, dict) or set(counts) != COUNTS or any(
                    type(counts[k]) is not int or counts[k] < 0 for k in COUNTS):
                raise ValueError("invalid incident confusion counts")
        if sum(r["baseline"].values()) != sum(r["candidate"].values()):
            raise ValueError("baseline and candidate denominators differ")
        if sum(r["baseline"].values()) == 0:
            raise ValueError("zero incident denominator")
        for label in (("tp", "fn"), ("fp", "tn")):
            if sum(r["baseline"][k] for k in label) != sum(
                    r["candidate"][k] for k in label):
                raise ValueError("baseline/candidate world labels differ")
        records.append(r)
    return records


def paired_cluster_analysis(raw: bytes, *, seed: int = 1729,
                            bootstrap_draws: int = 2000) -> dict:
    if type(seed) is not int or type(bootstrap_draws) is not int or not (
            200 <= bootstrap_draws <= 100000):
        raise ValueError("invalid reproducible bootstrap configuration")
    records = parse_trials(raw)
    if len(records) < 2:
        raise ValueError("at least two distinct claimed clusters required")
    # Each independently sourced trial is one sampling unit; do not pretend
    # correlated incidents within a cluster are independent replicates.
    effects = []
    for r in records:
        total = sum(r["baseline"].values())
        b = (r["baseline"]["tp"] + r["baseline"]["tn"]) / total
        c = (r["candidate"]["tp"] + r["candidate"]["tn"]) / total
        effects.append(c - b)
    n = len(effects)
    mean = sum(effects) / n
    rng = random.Random(seed)
    samples = sorted(sum(effects[rng.randrange(n)] for _ in range(n)) / n
                     for _ in range(bootstrap_draws))
    lo = samples[int(0.025 * bootstrap_draws)]
    hi = samples[min(bootstrap_draws - 1, math.ceil(0.975 * bootstrap_draws) - 1)]
    # Monte Carlo sign-flip test is valid only under exchangeability and a
    # symmetric null; this assumption is NOT verified by trial metadata.
    draws = 20000
    rng_sign = random.Random(seed + 1)
    extreme = sum(abs(sum(e * (1 if rng_sign.getrandbits(1) else -1)
                          for e in effects) / n) >= abs(mean) - 1e-14
                  for _ in range(draws))
    p = (extreme + 1) / (draws + 1)
    return {
        "status": "descriptive_cluster_level_analysis_only",
        "publication_ready": False,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "claimed_independent_clusters": n,
        "scenario_count": len({r["scenario_id"] for r in records}),
        "metric": "candidate_minus_baseline_accuracy",
        "mean_difference_pp": mean * 100,
        "cluster_bootstrap_percentile_95_ci_pp": [lo * 100, hi * 100],
        "bootstrap_draws": bootstrap_draws, "random_seed": seed,
        "exploratory_sign_flip_p_two_sided": p,
        "sign_flip_draws": draws,
        "per_cluster_difference_pp": [
            {"trial_id": r["trial_id"], "cluster_id": r["independent_cluster_id"],
             "difference_pp": effect * 100}
            for r, effect in zip(records, effects)],
        "limitations": [
            "Trial IDs, distinct source hashes and cluster labels are operator claims; independence is not externally attested.",
            "No independent verification of event truth, actual policy execution, capture completeness, or physical safety.",
            "Bootstrap treats entire trials as sampling units; percentile intervals may be unstable for few clusters.",
            "Sign-flip p-value is exploratory and assumes exchangeable symmetric cluster-level null effects.",
            "A sample count >=30 does not imply statistical significance, adequate power, or generalizability.",
            "Only matched test-split incident accuracy is compared; precision/recall, delay, resource use and safety require separate endpoints.",
        ],
    }


def main():
    p = argparse.ArgumentParser(description="Descriptive independent-cluster V2X trial comparison")
    p.add_argument("--trials-jsonl", type=Path, required=True)
    p.add_argument("--pinned-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--seed", type=int, default=1729)
    p.add_argument("--bootstrap-draws", type=int, default=2000)
    a = p.parse_args()
    raw = a.trials_jsonl.read_bytes()
    if hashlib.sha256(raw).hexdigest() != a.pinned_sha256:
        p.error("trial input differs from externally pinned source digest")
    report = paired_cluster_analysis(raw, seed=a.seed,
                                     bootstrap_draws=a.bootstrap_draws)
    if a.output.exists():
        p.error("refuse to overwrite existing analysis evidence")
    a.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"report_sha256": hashlib.sha256(a.output.read_bytes()).hexdigest(),
                      "publication_ready": False}))


if __name__ == "__main__":
    main()
