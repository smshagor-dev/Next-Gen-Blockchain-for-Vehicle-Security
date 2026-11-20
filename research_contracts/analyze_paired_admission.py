"""Paired, cluster-aware exploratory analysis of durable admission timing.

Reads raw benchmark JSON; never interprets repetitions as independent scientific
V2X trials or as automatic statistical significance. No third-party dependencies.
"""
import argparse
import json
import math
import random
import statistics
from pathlib import Path


def summarize(payload, *, resamples=2000, seed=20261120):
    if type(payload.get("schema")) is not int or payload["schema"] != 1 or not isinstance(payload.get("samples"), list):
        raise ValueError("unsupported benchmark schema")
    if not 100 <= resamples <= 100000:
        raise ValueError("resamples must be between 100 and 100000")
    trials = payload["samples"]
    if len(trials) < 2 or type(payload.get("repeats")) is not int or payload["repeats"] != len(trials):
        raise ValueError("inconsistent trial count")
    ratios = []
    orders = {"memory": [], "sqlite": []}
    for trial in trials:
        order = trial.get("order")
        if order not in (["memory", "sqlite"], ["sqlite", "memory"]):
            raise ValueError("invalid trial execution order")
        memory, sqlite = trial.get("memory_ns"), trial.get("sqlite_ns")
        if not isinstance(memory, list) or not isinstance(sqlite, list) or len(memory) != 3 or len(sqlite) != 3:
            raise ValueError("each trial requires three paired observations")
        if any(type(x) is not int or x <= 0 for x in memory + sqlite):
            raise ValueError("durations must be positive integer nanoseconds")
        # Treat the trial, not its three correlated operations, as the unit.
        # Subtract log totals rather than divide huge integers into a float:
        # the latter may overflow or underflow on adversarial JSON input.
        log_ratio = math.log(sum(sqlite)) - math.log(sum(memory))
        if not math.isfinite(log_ratio):
            raise ValueError("non-finite log runtime ratio")
        ratios.append(log_ratio)
        orders[order[0]].append(log_ratio)
    # Preserve the assigned first-execution strata in each bootstrap draw.
    # A pooled draw can accidentally change the order mix and confound
    # the overhead interval when first/second execution affects latency.
    if not all(orders.values()):
        raise ValueError("both first-execution order strata are required")
    rng = random.Random(seed)
    bootstrap = []
    for _ in range(resamples):
        draw = []
        for values in orders.values():
            draw.extend(values[rng.randrange(len(values))] for _ in values)
        bootstrap.append(statistics.mean(draw))
    bootstrap.sort()
    lo = bootstrap[int(0.025 * resamples)]
    hi = bootstrap[min(resamples - 1, int(0.975 * resamples))]
    # Avoid serializing Infinity for extreme but syntactically valid inputs.
    if any(abs(value) > 700 for value in ratios):
        raise ValueError("runtime ratio outside numerically reportable range")
    return {
        "analysis": "exploratory order-stratified trial-cluster bootstrap of log(sqlite/memory) runtime ratio",
        "trials": len(trials), "seed": seed, "resamples": resamples,
        "geometric_mean_runtime_ratio": math.exp(statistics.mean(ratios)),
        "percentile_bootstrap_95_interval": [math.exp(lo), math.exp(hi)],
        "first_executed_order_strata": {
            key: {"trials": len(values),
                  "geometric_mean_runtime_ratio": math.exp(statistics.mean(values)) if values else None}
            for key, values in orders.items()},
        "interpretation": "ratio > 1 means SQLite slower; interval is exploratory, not proof of security effectiveness",
        "limitations": [
            "Three operations within each trial are correlated and not independent samples",
            "Bootstrap assumes exchangeability within order strata despite possible time drift and OS/disk cache effects",
            "No significance claim based on n>=30; no hypothesis-test p-value reported",
            "No physical hardware, network, CAN, VeReMi, adversarial or safety-effectiveness evaluation"
        ]
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resamples", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20261120)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve() or args.output.exists():
        parser.error("output must be new and distinct from input")
    with args.input.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    report = summarize(payload, resamples=args.resamples, seed=args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, allow_nan=False)
        handle.write("\n")


if __name__ == "__main__":
    main()
