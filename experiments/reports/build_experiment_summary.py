"""Build a conservative Markdown summary from available experiment JSON files."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


RESULT_FILES = {
    "latency": "latency_results.json",
    "scalability": "scalability_results.json",
    "adversarial": "adversarial_results.json",
    "fl": "fl_results.json",
}


def _load_first(input_dir: Path, filename: str) -> tuple[Path | None, dict | None]:
    matches = sorted(input_dir.rglob(filename), key=lambda p: str(p))
    for path in matches:
        try:
            return path, json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
    return None, None


def discover_results(input_dir: Path) -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}
    for experiment, filename in RESULT_FILES.items():
        path, payload = _load_first(input_dir, filename)
        results[experiment] = {"path": path, "payload": payload}
    return results


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and not math.isnan(float(value))


def _numeric_items(row: dict) -> List[tuple[str, object]]:
    return [(key, value) for key, value in row.items() if _is_number(value)]


def _status_lines(payload: dict | None) -> List[str]:
    if payload is None:
        return ["- Result file: missing"]
    lines = [f"- `status`: `{payload.get('status', '')}`"]
    if payload.get("dataset_required") is True or payload.get("status") == "dataset_required":
        lines.append("- Dataset required: yes. No result metrics should be cited from this artifact.")
    if payload.get("measured_runtime_benchmark") is False:
        lines.append("- Runtime benchmark: no. Treat this as analysis/simulation or offline metric aggregation only.")
    if payload.get("statistical_significance") is False:
        lines.append("- Statistical significance: false.")
    return lines


def _rows(payload: dict | None) -> List[dict]:
    if not payload:
        return []
    rows = payload.get("rows", [])
    return rows if isinstance(rows, list) else []


def _section(title: str, experiment_key: str, results: Dict[str, Dict[str, object]], row_limit: int = 6) -> List[str]:
    item = results[experiment_key]
    path = item["path"]
    payload = item["payload"]
    lines = [f"## {title}", ""]
    if path is None or payload is None:
        lines.extend(["- Result file: missing", ""])
        return lines
    lines.append(f"- Source: `{path}`")
    lines.extend(_status_lines(payload))
    rows = _rows(payload)
    numeric_rows = []
    for row in rows:
        if isinstance(row, dict):
            nums = _numeric_items(row)
            if nums:
                numeric_rows.append((row, nums))
    if numeric_rows:
        lines.extend(["", "| row | numeric metrics found |", "| --- | --- |"])
        for idx, (row, nums) in enumerate(numeric_rows[:row_limit], start=1):
            label = str(row.get("component") or row.get("scope") or row.get("topology") or row.get("attack_type") or idx)
            metrics = ", ".join(f"`{key}={value}`" for key, value in nums)
            lines.append(f"| {label} | {metrics} |")
        if len(numeric_rows) > row_limit:
            lines.append(f"| ... | {len(numeric_rows) - row_limit} additional rows omitted from summary |")
    else:
        lines.extend(["", "No numeric result metrics available in this JSON artifact."])
    lines.append("")
    return lines


def _missing_todos(results: Dict[str, Dict[str, object]]) -> List[str]:
    labels = {
        "latency": "Latency benchmarks",
        "scalability": "Scalability communication analysis",
        "adversarial": "Adversarial detection evaluation",
        "fl": "Federated learning evaluation",
    }
    lines = ["## Missing Results / TODOs", ""]
    any_missing = False
    for key, label in labels.items():
        payload = results[key]["payload"]
        if payload is None:
            lines.append(f"- {label}: missing result file.")
            any_missing = True
        elif isinstance(payload, dict) and (payload.get("dataset_required") is True or payload.get("status") == "dataset_required"):
            lines.append(f"- {label}: dataset required before metrics can be cited.")
            any_missing = True
    if not any_missing:
        lines.append("- No missing result files detected by the aggregator. Review claim-safety notes before citing results.")
    lines.append("")
    return lines


def _claim_safety_notes() -> List[str]:
    return [
        "## Claim Safety Notes",
        "",
        "- Do not claim full PQ security.",
        "- Do not claim Sybil resistance under open registration.",
        "- Do not claim 51% attack resistance.",
        "- Do not claim 100% detection.",
        "- Do not claim statistically significant FL/adversarial results unless count/repeated runs support it.",
        "- Do not claim measured scalability from communication simulation.",
        "",
    ]


def build_summary(input_dir: Path, output: Path) -> Path:
    results = discover_results(input_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# OmniGuard V2X Experiment Summary",
        "",
        "This summary is generated only from available experiment JSON artifacts. It does not infer, impute, or fabricate missing metrics.",
        "",
        "## Summary",
        "",
    ]
    for key, filename in RESULT_FILES.items():
        path = results[key]["path"]
        payload = results[key]["payload"]
        if path is None or payload is None:
            lines.append(f"- `{filename}`: missing")
        else:
            lines.append(f"- `{filename}`: found at `{path}` with status `{payload.get('status', '')}`")
    lines.append("")
    lines.extend(_section("Latency Benchmarks", "latency", results))
    lines.extend(_section("Scalability Communication Analysis", "scalability", results))
    lines.extend(_section("Adversarial Detection Evaluation", "adversarial", results))
    lines.extend(_section("Federated Learning Evaluation", "fl", results))
    lines.extend(_missing_todos(results))
    lines.extend(_claim_safety_notes())
    output.write_text("\n".join(lines), encoding="utf-8")
    return output


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a conservative OmniGuard V2X experiment summary.")
    parser.add_argument("--input-dir", default="experiments/reports")
    parser.add_argument("--output", default="experiments/reports/experiment_summary.md")
    args = parser.parse_args(argv)
    output = build_summary(Path(args.input_dir), Path(args.output))
    print(json.dumps({"output": str(output)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
