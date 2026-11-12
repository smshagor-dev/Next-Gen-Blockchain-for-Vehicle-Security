"""Reproducible, exploratory paired-method comparisons from raw trial CSVs.

No dataset or metric is invented. Seed labels only count as independent
replicates when upstream execution actually used independent trials.
This tool cannot verify that experimental assumption.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence

CONDITIONS = (
    "experiment_id", "dataset_id", "dataset_version", "split_id",
    "attack_type", "node_count", "adversarial_fraction",
)
REQUIRED = (*CONDITIONS, "seed", "method", "run_id", "metric", "value")
OUTPUT_FIELDS = (
    *CONDITIONS, "metric", "candidate", "baseline", "direction", "pair_count",
    "candidate_mean", "baseline_mean", "mean_improvement", "paired_effect_dz",
    "bootstrap_ci95_lower", "bootstrap_ci95_upper", "p_value_two_sided",
    "holm_adjusted_p", "randomization_method", "inference_status",
    "statistical_significance", "publication_ready",
)


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_trials(path: Path) -> list[dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        missing = set(REQUIRED) - set(reader.fieldnames or ())
        if missing:
            raise ValueError("missing required CSV columns: " + ", ".join(sorted(missing)))
        trials: list[dict[str, Any]] = []
        seen = set()
        for line, raw in enumerate(reader, 2):
            if None in raw or any(raw.get(col) is None for col in REQUIRED):
                raise ValueError(f"malformed CSV row at line {line}")
            row: dict[str, Any] = {}
            for col in (*CONDITIONS, "method", "run_id", "metric"):
                value = raw[col].strip()
                if not value:
                    raise ValueError(f"empty {col} at CSV line {line}")
                row[col] = value
            try:
                row["node_count"] = int(row["node_count"])
                row["adversarial_fraction"] = float(row["adversarial_fraction"])
                row["seed"] = int(raw["seed"])
                row["value"] = float(raw["value"])
            except ValueError as exc:
                raise ValueError(f"invalid numeric trial field at CSV line {line}") from exc
            if (row["node_count"] < 1 or row["seed"] < 0
                    or not math.isfinite(row["adversarial_fraction"])
                    or not 0 <= row["adversarial_fraction"] <= 1
                    or not math.isfinite(row["value"])):
                raise ValueError(f"invalid or non-finite trial field at CSV line {line}")
            # Must be unique even if duplicate rows have different run_id labels.
            identity = (*[row[col] for col in CONDITIONS], row["seed"], row["method"], row["metric"])
            if identity in seen:
                raise ValueError(f"duplicate scenario/method/seed/metric trial at CSV line {line}")
            seen.add(identity)
            trials.append(row)
    if not trials:
        raise ValueError("no raw trials provided")
    return trials


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def bootstrap_paired_mean_ci(differences: list[float], *, draws: int, seed: int) -> tuple[float, float]:
    """Percentile CI: resample paired *trials*, never individual methods."""
    if len(differences) < 2 or draws < 200:
        raise ValueError("paired bootstrap needs >=2 differences and >=200 draws")
    rng = random.Random(seed)
    n = len(differences)
    means = [statistics.fmean(differences[rng.randrange(n)] for _ in range(n)) for _ in range(draws)]
    return _percentile(means, 0.025), _percentile(means, 0.975)


def sign_flip_p_value(differences: list[float], *, draws: int, seed: int) -> tuple[float, str]:
    """Two-sided paired sign-flip randomization under a symmetric/exchangeable null."""
    if len(differences) < 2:
        raise ValueError("sign-flip test needs >=2 paired differences")
    observed = abs(sum(differences))
    scale = max(1.0, observed)
    if len(differences) <= 16:
        count = 0
        total = 0
        for signs in itertools.product((-1, 1), repeat=len(differences)):
            total += 1
            simulated = abs(sum(d * sign for d, sign in zip(differences, signs)))
            count += simulated >= observed - 1e-12 * scale
        return count / total, "exact_sign_flip"
    if draws < 500:
        raise ValueError("Monte Carlo sign-flip needs >=500 draws")
    rng = random.Random(seed)
    exceed = 0
    for _ in range(draws):
        simulated = abs(sum(d if rng.getrandbits(1) else -d for d in differences))
        exceed += simulated >= observed - 1e-12 * scale
    return (exceed + 1) / (draws + 1), "monte_carlo_sign_flip"


def _valid_provenance(path: Path | None, csv_sha256: str) -> str:
    if path is None:
        return "missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("provenance manifest is unreadable or invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("provenance manifest must be a JSON object")
    if payload.get("raw_csv_sha256") != csv_sha256:
        raise ValueError("provenance raw_csv_sha256 does not match input CSV")
    needed = ("dataset_source", "dataset_version", "license", "split_protocol", "experiment_protocol", "source_commit")
    if any(not isinstance(payload.get(col), str) or not payload[col].strip() for col in needed):
        raise ValueError("provenance manifest missing required origin/protocol fields")
    # An internally consistent manifest is self-reported, not independently verified.
    return "hash_checked_self_reported"


def analyze(
    trials: list[dict[str, Any]], *, candidate: str, baseline: str,
    metric: str, direction: str, min_pairs: int = 10,
    bootstrap_draws: int = 5000, permutations: int = 9999,
    seed: int = 1729,
) -> list[dict[str, Any]]:
    if not candidate or not baseline or candidate == baseline:
        raise ValueError("candidate and baseline must be distinct non-empty methods")
    if not metric or direction not in {"higher", "lower"}:
        raise ValueError("metric and direction higher/lower are required")
    if min_pairs < 2 or bootstrap_draws < 200 or permutations < 500:
        raise ValueError("min_pairs >=2, bootstrap_draws >=200, and permutations >=500 required")
    cohorts: dict[tuple[Any, ...], dict[str, dict[int, float]]] = defaultdict(lambda: {candidate: {}, baseline: {}})
    for row in trials:
        if row["metric"] != metric or row["method"] not in {candidate, baseline}:
            continue
        key = tuple(row[field] for field in CONDITIONS)
        cohorts[key][row["method"]][row["seed"]] = row["value"]
    if not cohorts:
        raise ValueError("no candidate/baseline trials for requested metric")
    out: list[dict[str, Any]] = []
    for key in sorted(cohorts, key=lambda k: tuple(str(x) for x in k)):
        values = cohorts[key]
        candidate_seeds = set(values[candidate])
        baseline_seeds = set(values[baseline])
        if candidate_seeds != baseline_seeds:
            raise ValueError(f"unmatched paired trials for scenario {key}; missing/extra seeds cannot be silently dropped")
        sorted_seeds = sorted(candidate_seeds)
        a = [values[candidate][x] for x in sorted_seeds]
        b = [values[baseline][x] for x in sorted_seeds]
        improvement = [(x - y) if direction == "higher" else (y - x) for x, y in zip(a, b)]
        n = len(sorted_seeds)
        mean_delta = statistics.fmean(improvement)
        effect = mean_delta / statistics.stdev(improvement) if n >= 2 and statistics.stdev(improvement) > 0 else None
        scenario_seed = seed ^ int(hashlib.sha256(repr(key).encode("utf-8")).hexdigest()[:8], 16)
        row = {
            **dict(zip(CONDITIONS, key)), "metric": metric,
            "candidate": candidate, "baseline": baseline, "direction": direction,
            "pair_count": n, "candidate_mean": statistics.fmean(a),
            "baseline_mean": statistics.fmean(b), "mean_improvement": mean_delta,
            "paired_effect_dz": effect, "bootstrap_ci95_lower": None,
            "bootstrap_ci95_upper": None, "p_value_two_sided": None,
            "holm_adjusted_p": None, "randomization_method": None,
            "inference_status": "insufficient_pairs", "statistical_significance": False,
            "publication_ready": False,
        }
        if n >= min_pairs:
            lower, upper = bootstrap_paired_mean_ci(improvement, draws=bootstrap_draws, seed=scenario_seed)
            p_value, method = sign_flip_p_value(improvement, draws=permutations, seed=scenario_seed + 1)
            row.update(
                bootstrap_ci95_lower=lower, bootstrap_ci95_upper=upper,
                p_value_two_sided=p_value, randomization_method=method,
                inference_status="exploratory_unadjusted",
            )
        out.append(row)
    # Holm family-wise adjustment across all reported scenario tests; no automatic
    # declaration of significance without preregistration and assumption review.
    tested = sorted((r for r in out if r["p_value_two_sided"] is not None), key=lambda r: r["p_value_two_sided"])
    previous = 0.0
    for index, row in enumerate(tested):
        adjusted = min(1.0, (len(tested) - index) * row["p_value_two_sided"])
        previous = max(previous, adjusted)
        row["holm_adjusted_p"] = previous
    return out


def run(
    csv_file: Path, output_dir: Path, *, candidate: str, baseline: str,
    metric: str, direction: str, min_pairs: int = 10,
    bootstrap_draws: int = 5000, permutations: int = 9999,
    seed: int = 1729, provenance: Path | None = None,
) -> dict[str, Any]:
    csv_file = Path(csv_file)
    input_hash = _digest(csv_file)
    provenance_status = _valid_provenance(provenance, input_hash)
    data = read_trials(csv_file)
    results = analyze(
        data, candidate=candidate, baseline=baseline, metric=metric,
        direction=direction, min_pairs=min_pairs,
        bootstrap_draws=bootstrap_draws, permutations=permutations, seed=seed,
    )
    summary = {
        "analysis": "paired_baseline_comparison", "status": "exploratory_only",
        "source_file": str(csv_file), "source_sha256": input_hash,
        "provenance_status": provenance_status,
        "candidate": candidate, "baseline": baseline, "metric": metric,
        "direction": direction, "min_pairs": min_pairs,
        "bootstrap_draws": bootstrap_draws, "permutations": permutations,
        "analysis_seed": seed, "method": "paired_bootstrap_and_sign_flip_randomization",
        "multiplicity_correction": "Holm across analyzed scenarios",
        "publication_ready": False,
        "assumptions": [
            "Each seed corresponds to an independently executed paired trial; seed labels alone cannot prove independence.",
            "Paired sign-flip randomization assumes sign exchangeability under the null.",
            "Percentile paired bootstrap CI is exploratory and may be unreliable with small samples.",
            "Source/dataset labels and any self-reported provenance have not been independently verified.",
            "No data, benchmarks, attacks, or security guarantees are generated by this analyzer.",
        ],
        "rows": results,
    }
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_json = output_dir / "paired_results.json"
    out_csv = output_dir / "paired_results.csv"
    out_md = output_dir / "paired_report.md"
    out_json.write_text(json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    with out_csv.open("w", newline="", encoding="utf-8") as sink:
        writer = csv.DictWriter(sink, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(results)
    notes = [
        "# Exploratory paired baseline comparison", "",
        f"- Source SHA-256: {input_hash}", f"- Provenance: {provenance_status}",
        "- **Not publication-ready**: dataset authenticity, independent trial execution and preregistered analysis must be validated.",
        "- Positive improvement means candidate better after the declared metric direction.",
        "- CI: paired percentile bootstrap; p-value: two-sided sign-flip randomization; adjusted p: Holm across scenarios.",
        "- Effect size dz is mean paired improvement divided by its sample standard deviation; undefined when variance is zero.",
        "- Raw data are not included in this summary. See SHA-256 provenance and input CSV.", "",
        "## Results", "",
        "| Attack | N | Mean improvement | 95% bootstrap CI | Holm p | Status |",
        "| --- | ---: | ---: | --- | ---: | --- |",
    ]
    for row in results:
        ci = "not computed" if row["bootstrap_ci95_lower"] is None else f"[{row['bootstrap_ci95_lower']:.6g}, {row['bootstrap_ci95_upper']:.6g}]"
        p_value = "not computed" if row["holm_adjusted_p"] is None else f"{row['holm_adjusted_p']:.6g}"
        notes.append(f"| {row['attack_type']} | {row['pair_count']} | {row['mean_improvement']:.6g} | {ci} | {p_value} | {row['inference_status']} |")
    out_md.write_text("\n".join(notes) + "\n", encoding="utf-8")
    manifest = {
        "raw_input_sha256": input_hash,
        "analysis_output_sha256": {p.name: _digest(p) for p in (out_json, out_csv, out_md)},
        "provenance_manifest_sha256": _digest(provenance) if provenance else None,
        "publication_ready": False,
    }
    (output_dir / "paired_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Exploratory paired baseline analysis; never asserts research readiness.")
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--metric", required=True)
    parser.add_argument("--direction", required=True, choices=("higher", "lower"))
    parser.add_argument("--min-pairs", type=int, default=10)
    parser.add_argument("--bootstrap-draws", type=int, default=5000)
    parser.add_argument("--permutations", type=int, default=9999)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--provenance-manifest")
    args = parser.parse_args(argv)
    report = run(
        Path(args.input_csv), Path(args.output_dir), candidate=args.candidate,
        baseline=args.baseline, metric=args.metric, direction=args.direction,
        min_pairs=args.min_pairs, bootstrap_draws=args.bootstrap_draws,
        permutations=args.permutations, seed=args.seed,
        provenance=Path(args.provenance_manifest) if args.provenance_manifest else None,
    )
    print(json.dumps({"status": report["status"], "scenarios": len(report["rows"]), "publication_ready": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
