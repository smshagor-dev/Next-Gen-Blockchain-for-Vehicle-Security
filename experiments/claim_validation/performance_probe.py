"""Local decision-stage microbenchmark and deterministic freshness sensitivity.

Excludes network, crypto operations, evidence acquisition and disk IO from the
timed section. No latency SLA or independent deployment inference.
"""
from __future__ import annotations

import argparse
import csv
import gc
import json
import platform
import random
import statistics
import sys
import time
from pathlib import Path

from experiments.claim_validation.claim_gate import evaluate_claim
from experiments.claim_validation.design_reference import adjudicate
from experiments.claim_validation.paired_comparison import (
    DOMAINS, decode_observation, digest, load_rows, reference_and_metadata,
)
from experiments.claim_validation.design_analysis import write_csv

THRESHOLDS_MS = (1, 10, 100, 1000, 5000)
AGES_MS = (-1, 0, 1, 10, 100, 1000, 5000, 10000)
METHODS = ("posture_proxy", "declared_capability_proxy", "observed_gate")
BLOCKS = 30
PASSES_PER_BLOCK = 10
ORDER_SEED = 20261124


def prepare(domain, row):
    ref = adjudicate(domain, row)
    truth, posture, declared = reference_and_metadata(domain, row)
    if not ref["direct_agrees"] or truth is not ref["truth"]:
        raise ValueError("reference disagreement")
    return (row["expected_scope"], decode_observation(row), posture, declared, truth)


def call(method, claim, prepared):
    scope, obs, posture, declared, _ = prepared
    if method == "posture_proxy":
        return posture == "STRONG"
    if method == "declared_capability_proxy":
        return posture == "STRONG" and declared
    if method == "observed_gate":
        return evaluate_claim(claim, posture, obs, expected_scope=scope,
                              now_ns=obs.monotonic_ns).eligibility == "ELIGIBLE"
    raise ValueError("unknown method")


def freshness_rows(domain, prepared):
    claim = DOMAINS[domain][0]
    for scope, obs, posture, declared, truth in prepared:
        for threshold in THRESHOLDS_MS:
            for age in AGES_MS:
                result = evaluate_claim(claim, posture, obs, expected_scope=scope,
                                        now_ns=obs.monotonic_ns + age * 1_000_000,
                                        max_age_ns=threshold * 1_000_000)
                yield {"trial_scope": scope, "threshold_ms": threshold, "synthetic_age_ms": age,
                       "reference_positive": truth, "posture": posture,
                       "eligibility": result.eligibility, "reason": result.reason}


def summarize_freshness(rows):
    report = []
    for threshold in THRESHOLDS_MS:
        for age in AGES_MS:
            subset = [r for r in rows if r["threshold_ms"] == threshold and r["synthetic_age_ms"] == age]
            pos = sum(r["reference_positive"] for r in subset)
            neg = len(subset) - pos
            good = sum(r["reference_positive"] and r["eligibility"] == "ELIGIBLE" for r in subset)
            bad = sum(not r["reference_positive"] and r["eligibility"] == "ELIGIBLE" for r in subset)
            report.append({"threshold_ms": threshold, "synthetic_age_ms": age, "n": len(subset),
                           "reference_positive": pos, "reference_negative": neg,
                           "supported_eligible": good, "unsupported_eligible": bad,
                           "withheld": sum(r["eligibility"] == "WITHHELD" for r in subset),
                           "not_supported": sum(r["eligibility"] == "NOT_SUPPORTED" for r in subset),
                           "positive_eligibility_rate": good/pos if pos else None,
                           "unsupported_eligibility_rate": bad/neg if neg else None})
    return report


def benchmark(domain, prepared, blocks=BLOCKS, passes=PASSES_PER_BLOCK):
    if not prepared or blocks < 1 or passes < 1:
        raise ValueError("invalid benchmark size")
    claim = DOMAINS[domain][0]
    rng = random.Random(ORDER_SEED)
    results = []
    # Warm all methods equally; exclude warm-up from the reported samples.
    for method in METHODS:
        for row in prepared:
            call(method, claim, row)
    for block in range(blocks):
        shuffled = list(prepared)
        rng.shuffle(shuffled)
        methods = list(METHODS)
        rng.shuffle(methods)
        for position, method in enumerate(methods):
            gc.collect()
            start = time.perf_counter_ns()
            eligible_count = 0
            for _ in range(passes):
                for row in shuffled:
                    eligible_count += call(method, claim, row)
            elapsed = time.perf_counter_ns() - start
            calls = passes * len(shuffled)
            results.append({"block": block, "order_position": position, "method": method,
                            "calls": calls, "elapsed_ns": elapsed, "mean_ns_per_call": elapsed/calls,
                            "eligible_count": eligible_count})
    return results


def summarize_timing(rows):
    out = {}
    for method in METHODS:
        selected = [r for r in rows if r["method"] == method]
        values = [r["mean_ns_per_call"] for r in selected]
        out[method] = {"blocks": len(values), "calls": sum(r["calls"] for r in selected),
                       "median_block_mean_ns": statistics.median(values),
                       "min_block_mean_ns": min(values), "max_block_mean_ns": max(values)}
    by_block = {}
    for row in rows:
        by_block.setdefault(row["block"], {})[row["method"]] = row["mean_ns_per_call"]
    for method in METHODS[:-1]:
        delta = [v["observed_gate"]-v[method] for v in by_block.values()]
        out["gate_minus_" + method] = {"median_paired_block_delta_ns": statistics.median(delta),
                                       "min_delta_ns": min(delta), "max_delta_ns": max(delta)}
    return out


def run(domain, source, out):
    rows, revision = load_rows(domain, source)
    prepared = [prepare(domain, row) for row in rows]
    fresh = list(freshness_rows(domain, prepared))
    timing = benchmark(domain, prepared)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "freshness.csv", fresh)
    write_csv(out / "timing_blocks.csv", timing)
    report = {"domain": domain, "executed_sha": revision, "python": sys.version,
              "platform": platform.platform(), "clock": vars(time.get_clock_info("perf_counter")),
              "base_trials": len(prepared), "freshness_rows": len(fresh),
              "timing_blocks": BLOCKS, "timed_decisions": sum(r["calls"] for r in timing),
              "timing": summarize_timing(timing), "freshness": summarize_freshness(fresh),
              "source_trace_sha256": digest(source / "traces.jsonl"),
              "benchmark_source_sha256": digest(Path(__file__)),
              "artifact_sha256": {n: digest(out/n) for n in ("freshness.csv", "timing_blocks.csv")},
              "statistical_inference": False,
              "scope": "local predecoded decision microbenchmark; block means not individual-call tail latency",
              "excluded": ["cryptography", "network", "collector", "serialization", "disk IO"]}
    (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k:v for k,v in report.items() if k != "freshness"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", choices=DOMAINS, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.domain, args.source, args.out)
