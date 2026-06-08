"""CSV-backed federated-learning result aggregation for OmniGuard V2X.

When an input CSV is provided, this runner computes grouped descriptive
statistics from real FL experiment logs. Without input data it writes only a
dataset-required schema/TODO report and does not fabricate metrics.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

try:
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_csv, write_json
except ModuleNotFoundError:
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_csv, write_json


PEER_COUNTS = [10, 20, 50]
SEEDS = list(range(30))
ATTACKS = ["sign-flip", "label-flip", "gaussian-noise", "scaling-attack", "random-update", "backdoor"]
METRICS = ["accuracy", "precision", "recall", "f1", "attack_success_rate", "aggregation_latency_ms"]
DEFAULT_GROUP_BY = ["attack_type", "peer_count", "byzantine_fraction"]
REQUIRED_COLUMNS = ["seed", "peer_count", "byzantine_fraction", "attack_type", *METRICS]


@dataclass(frozen=True)
class FLConfig:
    peers: int
    seed: int
    attack: str
    model: str = "TODO_MODEL"
    dataset: str = "TODO_DATASET"


def build_plan(peers: Sequence[int] = PEER_COUNTS, seeds: Sequence[int] = SEEDS, attacks: Sequence[str] = ATTACKS) -> List[FLConfig]:
    return [FLConfig(int(peer), int(seed), str(attack)) for peer in peers for seed in seeds for attack in attacks]


def _parse_group_by(value: str | Sequence[str] | None) -> List[str]:
    if value is None:
        return list(DEFAULT_GROUP_BY)
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(part) for part in value]


def _load_rows(input_csv: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    with input_csv.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = set(REQUIRED_COLUMNS).difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"missing required CSV columns: {', '.join(sorted(missing))}")
        for i, row in enumerate(reader, start=2):
            parsed: Dict[str, object] = {
                "seed": int(row["seed"]),
                "peer_count": int(row["peer_count"]),
                "byzantine_fraction": float(row["byzantine_fraction"]),
                "attack_type": str(row["attack_type"]),
            }
            for metric in METRICS:
                try:
                    parsed[metric] = float(row[metric])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"invalid {metric} at CSV line {i}: {exc}") from exc
            rows.append(parsed)
    return rows


def _std(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def _round(value: float) -> float:
    if math.isnan(value):
        return value
    return round(float(value), 6)


def _stats_for(values: Sequence[float]) -> Dict[str, float]:
    vals = [float(v) for v in values]
    return {
        "mean": _round(statistics.fmean(vals)),
        "std": _round(_std(vals)),
        "min": _round(min(vals)),
        "max": _round(max(vals)),
    }


def grouped_statistics(rows: Sequence[Dict[str, object]], group_by: Sequence[str]) -> List[Dict[str, object]]:
    groups: Dict[tuple, List[Dict[str, object]]] = {}
    for row in rows:
        key = tuple(row[column] for column in group_by)
        groups.setdefault(key, []).append(row)

    out: List[Dict[str, object]] = []
    for key in sorted(groups, key=lambda item: tuple(str(part) for part in item)):
        grouped_rows = groups[key]
        result: Dict[str, object] = {
            "group_by": ",".join(group_by),
            "count": len(grouped_rows),
            "statistical_significance": len(grouped_rows) >= 30,
            "dataset_required": False,
        }
        for column, value in zip(group_by, key):
            result[column] = value
        for metric in METRICS:
            stats = _stats_for([float(row[metric]) for row in grouped_rows])
            for stat_name, stat_value in stats.items():
                result[f"{metric}_{stat_name}"] = stat_value
        out.append(result)
    return out


def _dataset_required_rows(group_by: Sequence[str]) -> List[Dict[str, object]]:
    row: Dict[str, object] = {
        "group_by": ",".join(group_by),
        "count": "",
        "statistical_significance": False,
        "dataset_required": True,
    }
    for column in group_by:
        row[column] = f"TODO_{column.upper()}"
    for metric in METRICS:
        for stat_name in ["mean", "std", "min", "max"]:
            row[f"{metric}_{stat_name}"] = ""
    return [row]


def _fieldnames(group_by: Sequence[str]) -> List[str]:
    fields = ["group_by", *group_by, "count", "statistical_significance", "dataset_required"]
    for metric in METRICS:
        for stat_name in ["mean", "std", "min", "max"]:
            fields.append(f"{metric}_{stat_name}")
    return fields


def _write_fl_markdown(path: Path, summary: Dict[str, object], rows: Sequence[Dict[str, object]], group_by: Sequence[str]) -> Path:
    ensure_dir(path.parent)
    lines = [
        "# Federated Learning Result Aggregation",
        "",
        "This runner computes grouped statistics only from provided FL experiment CSV logs. It does not fabricate FL results.",
        "",
        "## Input Schema",
        "",
    ]
    for column in REQUIRED_COLUMNS:
        lines.append(f"- `{column}`")
    lines.extend(
        [
            "",
            "## Statistic Definitions",
            "",
            "- `count`: number of CSV rows in the group.",
            "- `mean`: arithmetic mean for each metric.",
            "- `std`: sample standard deviation for each metric; `0` for single-row groups.",
            "- `min` / `max`: observed metric bounds within the group.",
            "- `statistical_significance`: `true` only when group `count >= 30`.",
            "",
            "## Summary",
            "",
        ]
    )
    for key, value in summary.items():
        if key != "artifacts":
            lines.append(f"- `{key}`: `{value}`")
    if summary.get("status") == "dataset_required":
        lines.extend(
            [
                "",
                "No input CSV was provided, so no FL metric statistics were computed.",
                "Provide `--input-csv` with the schema above to generate grouped statistics.",
            ]
        )
    fields = _fieldnames(group_by)
    lines.extend(["", "## Results", ""])
    lines.append("| " + " | ".join(fields) + " |")
    lines.append("| " + " | ".join(["---"] * len(fields)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_fl_plot(path: Path, rows: Sequence[Dict[str, object]], dataset_required: bool) -> Path:
    ensure_dir(path.parent)
    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(9, 5))
        if dataset_required:
            ax.axis("off")
            ax.text(0.5, 0.55, "Dataset Required", ha="center", va="center", fontsize=15, weight="bold")
            ax.text(0.5, 0.4, "Provide FL experiment logs to compute grouped statistics.", ha="center", va="center", fontsize=10)
        else:
            labels = [str(row.get("attack_type", i)) for i, row in enumerate(rows)]
            values = [float(row.get("accuracy_mean", 0.0)) for row in rows]
            ax.bar(labels, values, color="#2f80ed")
            ax.set_ylabel("accuracy mean")
            ax.set_title("FL Accuracy Mean by Group")
            ax.set_ylim(0, 1)
            ax.tick_params(axis="x", rotation=35)
        fig.tight_layout()
        fig.savefig(path, dpi=160)
        plt.close(fig)
    except Exception:
        path.write_bytes(
            bytes.fromhex(
                "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
                "0000000d49444154789c6360000002000100ffff03000006000557bfab3d000000"
                "0049454e44ae426082"
            )
        )
    return path


def run(
    output_dir: Path,
    input_csv: Path | None = None,
    seed: int = 0,
    group_by: Sequence[str] | str | None = None,
) -> dict:
    ensure_dir(output_dir)
    group_columns = _parse_group_by(group_by)
    dataset_required = input_csv is None
    if dataset_required:
        rows = _dataset_required_rows(group_columns)
        status = "dataset_required"
        input_rows = 0
    else:
        raw_rows = _load_rows(Path(input_csv))
        missing_group_columns = set(group_columns).difference(REQUIRED_COLUMNS)
        if missing_group_columns:
            raise ValueError(f"group-by columns are not present in the input schema: {', '.join(sorted(missing_group_columns))}")
        rows = grouped_statistics(raw_rows, group_columns)
        status = "computed_from_fl_csv"
        input_rows = len(raw_rows)
    summary = {
        "experiment": "federated_learning",
        "status": status,
        "created_at": utc_now(),
        "input_csv": str(input_csv) if input_csv else "",
        "input_rows": input_rows,
        "group_by": ",".join(group_columns),
        "metrics": ",".join(METRICS),
        "dataset_required": dataset_required,
        "seed": int(seed),
    }
    fields = _fieldnames(group_columns)
    csv_path = write_csv(output_dir / "fl_results.csv", rows, fields)
    json_path = write_json(output_dir / "fl_results.json", {**summary, "rows": rows})
    md_path = _write_fl_markdown(output_dir / "fl_report.md", summary, rows, group_columns)
    png_path = _write_fl_plot(output_dir / "fl_plot.png", rows, dataset_required)
    return {**summary, "rows": rows, "artifacts": artifact_manifest([csv_path, json_path, md_path, png_path])}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate OmniGuard V2X FL experiment metrics from CSV logs.")
    parser.add_argument("--input-csv")
    parser.add_argument("--output-dir", default=str(DEFAULT_REPORT_DIR / "fl"))
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--group-by", default=",".join(DEFAULT_GROUP_BY))
    args = parser.parse_args(argv)
    payload = run(
        Path(args.output_dir),
        input_csv=Path(args.input_csv) if args.input_csv else None,
        seed=args.seed,
        group_by=args.group_by,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
