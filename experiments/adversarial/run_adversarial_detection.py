"""CSV-backed adversarial-detection evaluation for OmniGuard V2X.

When a labeled CSV is provided, this runner computes confusion-matrix metrics
from detector scores. Without an input CSV it writes only a dataset-required
schema/TODO report and does not fabricate results.
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

try:
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_csv, write_json
except ModuleNotFoundError:
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_csv, write_json


SCENARIOS = ["realistic-speed-range", "replay-attack", "timing-attack", "gps-drift", "sensor-noise", "gradual-poisoning"]
SEEDS = list(range(30))
METRICS = [
    "tp",
    "fp",
    "tn",
    "fn",
    "precision",
    "recall",
    "specificity",
    "f1",
    "accuracy",
    "false_positive_rate",
    "false_negative_rate",
]


@dataclass(frozen=True)
class AdversarialConfig:
    scenario: str
    seed: int
    dataset: str = "TODO_DATASET"
    detector_profile: str = "TODO_DETECTOR_PROFILE"


def build_plan(scenarios: Sequence[str] = SCENARIOS, seeds: Sequence[int] = SEEDS) -> List[AdversarialConfig]:
    return [AdversarialConfig(str(scenario), int(seed)) for scenario in scenarios for seed in seeds]


def _safe_div(num: int | float, den: int | float) -> float:
    if den == 0:
        return 0.0
    return float(num) / float(den)


def _metrics_from_counts(scope: str, attack_type: str, tp: int, fp: int, tn: int, fn: int) -> Dict[str, object]:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    f1 = _safe_div(2.0 * precision * recall, precision + recall)
    total = tp + fp + tn + fn
    return {
        "scope": scope,
        "attack_type": attack_type,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "specificity": round(specificity, 6),
        "f1": round(f1, 6),
        "accuracy": round(_safe_div(tp + tn, total), 6),
        "false_positive_rate": round(_safe_div(fp, fp + tn), 6),
        "false_negative_rate": round(_safe_div(fn, fn + tp), 6),
        "sample_count": total,
        "measured_runtime_benchmark": False,
        "dataset_required": False,
        "statistical_significance": False,
    }


def _counts(rows: Sequence[Dict[str, object]]) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for row in rows:
        label = int(row["label"])
        predicted_attack = bool(row["predicted_attack"])
        if label == 1 and predicted_attack:
            tp += 1
        elif label == 0 and predicted_attack:
            fp += 1
        elif label == 0 and not predicted_attack:
            tn += 1
        elif label == 1 and not predicted_attack:
            fn += 1
    return tp, fp, tn, fn


def _load_labeled_rows(
    input_csv: Path,
    threshold: float,
    label_column: str,
    score_column: str,
    attack_column: str,
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    with input_csv.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {label_column, score_column, attack_column}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"missing required CSV columns: {', '.join(sorted(missing))}")
        for i, row in enumerate(reader, start=2):
            try:
                label = int(row[label_column])
                score = float(row[score_column])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid label/score at CSV line {i}: {exc}") from exc
            if label not in {0, 1}:
                raise ValueError(f"invalid label at CSV line {i}: expected 0 or 1")
            if not 0.0 <= score <= 1.0:
                raise ValueError(f"invalid score at CSV line {i}: expected value between 0 and 1")
            rows.append(
                {
                    "label": label,
                    "score": score,
                    "attack_type": str(row[attack_column] or "unknown"),
                    "predicted_attack": score >= threshold,
                }
            )
    return rows


def evaluate_rows(rows: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    if not rows:
        return []
    evaluated = [_metrics_from_counts("overall", "overall", *_counts(rows))]
    attack_types = sorted({str(row["attack_type"]) for row in rows})
    for attack_type in attack_types:
        subset = [row for row in rows if str(row["attack_type"]) == attack_type]
        evaluated.append(_metrics_from_counts("per_attack_type", attack_type, *_counts(subset)))
    return evaluated


def _dataset_required_rows() -> List[Dict[str, object]]:
    return [
        {
            "scope": "schema_example",
            "attack_type": "TODO_ATTACK_TYPE",
            "tp": "",
            "fp": "",
            "tn": "",
            "fn": "",
            "precision": "",
            "recall": "",
            "specificity": "",
            "f1": "",
            "accuracy": "",
            "false_positive_rate": "",
            "false_negative_rate": "",
            "sample_count": "",
            "measured_runtime_benchmark": False,
            "dataset_required": True,
            "statistical_significance": False,
        }
    ]


def _write_adversarial_markdown(path: Path, summary: Dict[str, object], rows: Sequence[Dict[str, object]]) -> Path:
    ensure_dir(path.parent)
    lines = [
        "# Adversarial Detection Evaluation",
        "",
        "This runner computes detection metrics only from a provided labeled CSV. It does not fabricate adversarial datasets or results.",
        "",
        "## Input Schema",
        "",
        "- `label`: `0` for normal, `1` for attack.",
        "- `score`: detector score between `0` and `1`.",
        "- `attack_type`: attack family or scenario label.",
        "",
        "## Metric Definitions",
        "",
        "- `precision = TP / (TP + FP)`",
        "- `recall = TP / (TP + FN)`",
        "- `specificity = TN / (TN + FP)`",
        "- `F1 = 2 * precision * recall / (precision + recall)`",
        "- `accuracy = (TP + TN) / total`",
        "- `false_positive_rate = FP / (FP + TN)`",
        "- `false_negative_rate = FN / (FN + TP)`",
        "",
        "## Summary",
        "",
    ]
    for key, value in summary.items():
        if key != "artifacts":
            lines.append(f"- `{key}`: `{value}`")
    if summary.get("status") == "dataset_required":
        lines.extend(
            [
                "",
                "No input CSV was provided, so no metric values were computed.",
                "Provide `--input-csv` with the schema above to generate results.",
            ]
        )
    fields = [
        "scope",
        "attack_type",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall",
        "specificity",
        "f1",
        "accuracy",
        "false_positive_rate",
        "false_negative_rate",
        "sample_count",
        "measured_runtime_benchmark",
        "dataset_required",
        "statistical_significance",
    ]
    lines.extend(["", "## Results", ""])
    lines.append("| " + " | ".join(fields) + " |")
    lines.append("| " + " | ".join(["---"] * len(fields)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_adversarial_plot(path: Path, rows: Sequence[Dict[str, object]], dataset_required: bool) -> Path:
    ensure_dir(path.parent)
    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(9, 5))
        if dataset_required:
            ax.axis("off")
            ax.text(0.5, 0.55, "Dataset Required", ha="center", va="center", fontsize=15, weight="bold")
            ax.text(0.5, 0.4, "Provide a labeled CSV to compute adversarial metrics.", ha="center", va="center", fontsize=10)
        else:
            plotted = [row for row in rows if row.get("scope") == "per_attack_type"]
            labels = [str(row["attack_type"]) for row in plotted]
            values = [float(row["f1"]) for row in plotted]
            ax.bar(labels, values, color="#2f80ed")
            ax.set_ylabel("F1")
            ax.set_title("Adversarial Detection F1 by Attack Type")
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
    threshold: float = 0.5,
    label_column: str = "label",
    score_column: str = "score",
    attack_column: str = "attack_type",
    seed: int = 0,
) -> dict:
    ensure_dir(output_dir)
    dataset_required = input_csv is None
    if dataset_required:
        rows = _dataset_required_rows()
        status = "dataset_required"
        input_rows = 0
    else:
        labeled_rows = _load_labeled_rows(Path(input_csv), threshold, label_column, score_column, attack_column)
        rows = evaluate_rows(labeled_rows)
        status = "computed_from_labeled_csv"
        input_rows = len(labeled_rows)
    summary = {
        "experiment": "adversarial_detection",
        "status": status,
        "created_at": utc_now(),
        "input_csv": str(input_csv) if input_csv else "",
        "threshold": float(threshold),
        "label_column": label_column,
        "score_column": score_column,
        "attack_column": attack_column,
        "input_rows": input_rows,
        "metrics": ",".join(METRICS),
        "measured_runtime_benchmark": False,
        "dataset_required": dataset_required,
        "statistical_significance": False,
        "seed": int(seed),
    }
    fields = [
        "scope",
        "attack_type",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall",
        "specificity",
        "f1",
        "accuracy",
        "false_positive_rate",
        "false_negative_rate",
        "sample_count",
        "measured_runtime_benchmark",
        "dataset_required",
        "statistical_significance",
    ]
    csv_path = write_csv(output_dir / "adversarial_results.csv", rows, fields)
    json_path = write_json(output_dir / "adversarial_results.json", {**summary, "rows": rows})
    md_path = _write_adversarial_markdown(output_dir / "adversarial_report.md", summary, rows)
    png_path = _write_adversarial_plot(output_dir / "adversarial_plot.png", rows, dataset_required)
    return {**summary, "rows": rows, "artifacts": artifact_manifest([csv_path, json_path, md_path, png_path])}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate OmniGuard V2X adversarial detection metrics from labeled CSV.")
    parser.add_argument("--input-csv")
    parser.add_argument("--output-dir", default=str(DEFAULT_REPORT_DIR / "adversarial"))
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--score-column", default="score")
    parser.add_argument("--attack-column", default="attack_type")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    payload = run(
        Path(args.output_dir),
        input_csv=Path(args.input_csv) if args.input_csv else None,
        threshold=args.threshold,
        label_column=args.label_column,
        score_column=args.score_column,
        attack_column=args.attack_column,
        seed=args.seed,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
