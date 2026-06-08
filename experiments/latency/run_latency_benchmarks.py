"""Local latency benchmark runner for OmniGuard V2X prototype components.

Only callable local components are measured. Unavailable components are marked
as skipped; no values are fabricated.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

try:
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_csv, write_json
except ModuleNotFoundError:
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_csv, write_json


START_MODES = ["cold-start", "warm-start"]
PERCENTILES = ["p50", "p95", "p99"]
COMPONENTS = [
    "security_capabilities",
    "identity_security",
    "consensus_security",
    "pedersen_privacy",
    "reviewer_audit",
    "blockchain_append_validate",
    "fl_validation",
]

NUMERIC_FIELDS = [
    "cold_start_ms",
    "warm_start_p50_ms",
    "warm_start_p95_ms",
    "warm_start_p99_ms",
    "mean_ms",
    "std_ms",
    "min_ms",
    "max_ms",
]

RAW_TRACE_FIELDS = ["component", "iteration", "phase", "latency_ms", "seed", "timestamp_utc", "status"]
RESOURCE_FIELDS = [
    "resource_profiling_status",
    "resource_profiling_reason",
    "process_cpu_percent_before",
    "process_cpu_percent_after",
    "rss_mb_before",
    "rss_mb_after",
    "memory_delta_mb",
]


@dataclass(frozen=True)
class LatencyConfig:
    component: str
    start_mode: str = "warm-start"
    iterations: int = 1000
    seed: int = 0


def build_plan(components: Sequence[str] = COMPONENTS, modes: Sequence[str] = START_MODES) -> List[LatencyConfig]:
    return [LatencyConfig(str(component), str(mode)) for component in components for mode in modes]


def _measure_once(fn: Callable[[], object]) -> float:
    start = time.perf_counter_ns()
    fn()
    end = time.perf_counter_ns()
    return (end - start) / 1_000_000.0


def _percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return math.nan
    vals = sorted(float(v) for v in values)
    if len(vals) == 1:
        return vals[0]
    rank = (len(vals) - 1) * pct
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return vals[int(rank)]
    weight = rank - lo
    return vals[lo] * (1.0 - weight) + vals[hi] * weight


def _stats(cold_ms: float, warm_values: Sequence[float]) -> Dict[str, float]:
    vals = [float(v) for v in warm_values]
    return {
        "cold_start_ms": cold_ms,
        "warm_start_p50_ms": _percentile(vals, 0.50),
        "warm_start_p95_ms": _percentile(vals, 0.95),
        "warm_start_p99_ms": _percentile(vals, 0.99),
        "mean_ms": statistics.fmean(vals) if vals else math.nan,
        "std_ms": statistics.pstdev(vals) if len(vals) > 1 else 0.0,
        "min_ms": min(vals) if vals else math.nan,
        "max_ms": max(vals) if vals else math.nan,
    }


def _round_stats(row: Dict[str, object]) -> Dict[str, object]:
    out = dict(row)
    for key in [*NUMERIC_FIELDS, *RESOURCE_FIELDS]:
        if isinstance(out.get(key), (int, float)) and not math.isnan(float(out[key])):
            out[key] = round(float(out[key]), 6)
    return out


def _empty_resource_fields(status: str = "disabled", reason: str = "") -> Dict[str, object]:
    return {
        "resource_profiling_status": status,
        "resource_profiling_reason": reason,
        "process_cpu_percent_before": None,
        "process_cpu_percent_after": None,
        "rss_mb_before": None,
        "rss_mb_after": None,
        "memory_delta_mb": None,
    }


def _resource_probe(profile_resources: bool) -> Tuple[Optional[object], str, str]:
    if not profile_resources:
        return None, "disabled", ""
    try:
        import psutil
    except ImportError:
        return None, "skipped", "psutil unavailable"
    return psutil.Process(os.getpid()), "enabled", ""


def _sample_resources(process: object) -> Tuple[float, float]:
    cpu_percent = float(process.cpu_percent(interval=None))
    rss_mb = float(process.memory_info().rss) / (1024.0 * 1024.0)
    return cpu_percent, rss_mb


def _resource_delta(before: Optional[Tuple[float, float]], after: Optional[Tuple[float, float]]) -> Dict[str, object]:
    if before is None or after is None:
        return _empty_resource_fields()
    cpu_before, rss_before = before
    cpu_after, rss_after = after
    return _round_stats(
        {
            "resource_profiling_status": "measured",
            "resource_profiling_reason": "",
            "process_cpu_percent_before": cpu_before,
            "process_cpu_percent_after": cpu_after,
            "rss_mb_before": rss_before,
            "rss_mb_after": rss_after,
            "memory_delta_mb": rss_after - rss_before,
        }
    )


def _trace_row(
    component: str,
    iteration: int,
    phase: str,
    latency_ms: float,
    seed: int,
    status: str,
    resources: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    resource_values = resources if resources is not None else {}
    return {
        "component": component,
        "iteration": int(iteration),
        "phase": phase,
        "latency_ms": round(float(latency_ms), 6),
        "seed": int(seed),
        "timestamp_utc": utc_now(),
        "status": status,
        **resource_values,
    }


def _component_callables(seed: int) -> List[Tuple[str, Callable[[], Callable[[], object]]]]:
    random.seed(seed)

    def security_capabilities_setup() -> Callable[[], object]:
        from security_capabilities import security_capability_output

        return lambda: security_capability_output(False)

    def identity_security_setup() -> Callable[[], object]:
        from identity_security import identity_security_metadata

        return identity_security_metadata

    def consensus_security_setup() -> Callable[[], object]:
        from consensus_security import consensus_security_metadata

        return consensus_security_metadata

    def pedersen_privacy_setup() -> Callable[[], object]:
        from zkp_privacy import pedersen_privacy_metadata

        return pedersen_privacy_metadata

    def reviewer_audit_setup() -> Callable[[], object]:
        from security_capabilities import reviewer_audit_metadata

        return reviewer_audit_metadata

    def fl_validation_setup() -> Callable[[], object]:
        from federated_learning import fl_validation_metadata

        return fl_validation_metadata

    def blockchain_append_validate_setup() -> Callable[[], object]:
        benchmark_env = {
            "SMARTCAR_CHECKPOINT_ENABLED": "0",
            "SMARTCAR_PRUNING_ENABLED": "0",
            "SMARTCAR_FL_ENABLED": "0",
            "SMARTCAR_STORAGE_ENCRYPTION": "0",
            "SMARTCAR_PLATOON_POP_ENABLED": "0",
            "SMARTCAR_EDGE_ENABLED": "0",
        }
        old_env = {key: os.environ.get(key) for key in benchmark_env}
        os.environ.update(benchmark_env)
        from blockchain import SmartCarBlockchain, TelemetryData

        temp_dir = tempfile.TemporaryDirectory(prefix="omniguard_latency_")
        chain_file = str(Path(temp_dir.name) / "latency_chain.json")
        try:
            bc = SmartCarBlockchain(
                vehicle_id=f"LATENCY_BENCH_{seed}",
                password="latency_password",
                auth_token="latency_token",
                chain_file=chain_file,
            )
        finally:
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        counter = {"i": 0}

        def call() -> object:
            counter["i"] += 1
            tel = TelemetryData(
                speed=35.0 + (counter["i"] % 5),
                obstacle_distance=120.0,
                timestamp=bc._now(),
            )
            block = bc.push_telemetry(tel, "LATENCY:BENCHMARK")
            return {"block_index": block.index, "chain_valid": bc.verify_chain()}

        # Keep temp_dir alive through closure.
        call._temp_dir = temp_dir  # type: ignore[attr-defined]
        return call

    return [
        ("security_capabilities", security_capabilities_setup),
        ("identity_security", identity_security_setup),
        ("consensus_security", consensus_security_setup),
        ("pedersen_privacy", pedersen_privacy_setup),
        ("reviewer_audit", reviewer_audit_setup),
        ("blockchain_append_validate", blockchain_append_validate_setup),
        ("fl_validation", fl_validation_setup),
    ]


def _benchmark_component(
    component: str,
    setup: Callable[[], Callable[[], object]],
    iterations: int,
    warmup: int,
    seed: int,
    mode: str,
    resource_process: Optional[object] = None,
    resource_status: str = "disabled",
    resource_reason: str = "",
) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    base = {
        "component": component,
        "mode": mode,
        "iterations": int(iterations),
        "warmup": int(warmup),
        "seed": int(seed),
        "measured_iterations": 0,
        **_empty_resource_fields(resource_status, resource_reason),
    }
    traces: List[Dict[str, object]] = []
    try:
        fn = setup()
    except Exception as exc:
        return {**base, "status": "skipped", "reason": f"component unavailable: {exc}"}, traces

    try:
        resource_before = _sample_resources(resource_process) if resource_process is not None else None
        cold_ms = _measure_once(fn)
        traces.append(_trace_row(component, 0, "cold", cold_ms, seed, "measured"))
        for i in range(max(0, int(warmup))):
            warmup_ms = _measure_once(fn)
            traces.append(_trace_row(component, i, "warmup", warmup_ms, seed, "measured"))
        warm_values = []
        for i in range(max(1, int(iterations))):
            measured_ms = _measure_once(fn)
            traces.append(_trace_row(component, i, "measured", measured_ms, seed, "measured"))
            warm_values.append(measured_ms)
        resource_after = _sample_resources(resource_process) if resource_process is not None else None
    except Exception as exc:
        return {**base, "status": "skipped", "reason": f"component unavailable: {exc}"}, traces
    finally:
        temp_dir = getattr(locals().get("fn", None), "_temp_dir", None)
        if temp_dir is not None:
            temp_dir.cleanup()

    row = {
        **base,
        "status": "measured",
        "reason": "",
        "measured_iterations": len(warm_values),
        **_stats(cold_ms, warm_values),
        **(
            _resource_delta(resource_before, resource_after)
            if resource_process is not None
            else _empty_resource_fields(resource_status, resource_reason)
        ),
    }
    row = _round_stats(row)
    resource_values = {field: row.get(field) for field in RESOURCE_FIELDS}
    for trace in traces:
        trace.update(resource_values)
    return row, traces


def _write_latency_markdown(path: Path, summary: Dict[str, object], rows: Sequence[Dict[str, object]]) -> Path:
    ensure_dir(path.parent)
    lines = [
        "# Latency Benchmark Report",
        "",
        "This report contains measured local prototype callable latency where components were importable.",
        "Skipped rows are not measurements.",
        "",
        "## Summary",
        "",
    ]
    for key, value in summary.items():
        if key != "artifacts":
            lines.append(f"- `{key}`: `{value}`")
    if summary.get("resource_profiling_status") == "skipped":
        lines.extend(
            [
                "",
                "Resource profiling: skipped",
                "Install with: `pip install -r requirements-experiments.txt`",
            ]
        )
    lines.extend(["", "## Results", ""])
    fields = [
        "component",
        "status",
        "measured_iterations",
        "cold_start_ms",
        "warm_start_p50_ms",
        "warm_start_p95_ms",
        "warm_start_p99_ms",
        "mean_ms",
        "std_ms",
        "min_ms",
        "max_ms",
        *RESOURCE_FIELDS,
        "reason",
    ]
    lines.append("| " + " | ".join(fields) + " |")
    lines.append("| " + " | ".join(["---"] * len(fields)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(f, "")) for f in fields) + " |")
    skipped = [row for row in rows if row.get("status") == "skipped"]
    lines.extend(["", "## Skipped Components", ""])
    if skipped:
        for row in skipped:
            lines.append(f"- `{row.get('component')}`: {row.get('reason')}")
    else:
        lines.append("None.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_latency_plot(path: Path, rows: Sequence[Dict[str, object]]) -> Path:
    ensure_dir(path.parent)
    measured = [r for r in rows if r.get("status") == "measured"]
    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(10, 5))
        labels = [str(r["component"]) for r in measured]
        values = [float(r["warm_start_p50_ms"]) for r in measured]
        ax.bar(labels, values, color="#2f80ed")
        ax.set_ylabel("warm start p50 latency (ms)")
        ax.set_title("OmniGuard V2X Local Component Latency")
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
    iterations: int = 1000,
    warmup: int = 100,
    seed: int = 0,
    mode: str = "local",
    export_raw: bool = False,
    profile_resources: bool = False,
) -> dict:
    ensure_dir(output_dir)
    if mode != "local":
        raise ValueError("Only --mode local is currently implemented.")
    resource_process, resource_status, resource_reason = _resource_probe(profile_resources)
    rows = []
    raw_traces = []
    for component, setup in _component_callables(seed):
        row, traces = _benchmark_component(
            component,
            setup,
            iterations=iterations,
            warmup=warmup,
            seed=seed,
            mode=mode,
            resource_process=resource_process,
            resource_status=resource_status,
            resource_reason=resource_reason,
        )
        rows.append(row)
        raw_traces.extend(traces)
    summary = {
        "experiment": "latency",
        "status": "measured_local_components",
        "created_at": utc_now(),
        "mode": mode,
        "iterations": int(iterations),
        "warmup": int(warmup),
        "seed": int(seed),
        "raw_traces_exported": bool(export_raw),
        "raw_trace_rows": len(raw_traces) if export_raw else 0,
        "resource_profiling_requested": bool(profile_resources),
        "resource_profiling_status": "measured" if resource_process is not None else resource_status,
        "resource_profiling_reason": resource_reason,
        "measured_components": sum(1 for row in rows if row.get("status") == "measured"),
        "skipped_components": sum(1 for row in rows if row.get("status") == "skipped"),
    }
    fields = ["component", "mode", "iterations", "warmup", "seed", "status", "reason", "measured_iterations", *NUMERIC_FIELDS, *RESOURCE_FIELDS]
    csv_path = write_csv(output_dir / "latency_results.csv", rows, fields)
    json_path = write_json(output_dir / "latency_results.json", {**summary, "rows": rows})
    md_path = _write_latency_markdown(output_dir / "latency_report.md", summary, rows)
    png_path = _write_latency_plot(output_dir / "latency_plot.png", rows)
    artifacts = [csv_path, json_path, md_path, png_path]
    if export_raw:
        raw_fields = [*RAW_TRACE_FIELDS, *RESOURCE_FIELDS] if profile_resources else RAW_TRACE_FIELDS
        raw_csv_path = write_csv(output_dir / "latency_raw_traces.csv", raw_traces, raw_fields)
        raw_json_path = write_json(
            output_dir / "latency_raw_traces.json",
            {
                "created_at": utc_now(),
                "schema": raw_fields,
                "rows": raw_traces,
            },
        )
        artifacts.extend([raw_csv_path, raw_json_path])
    return {**summary, "rows": rows, "artifacts": artifact_manifest(artifacts)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run OmniGuard V2X local latency benchmarks.")
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--output-dir", default=str(DEFAULT_REPORT_DIR / "latency"))
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--mode", default="local", choices=["local"])
    parser.add_argument("--export-raw", action="store_true", help="Export per-iteration raw latency traces.")
    parser.add_argument("--profile-resources", action="store_true", help="Record lightweight process CPU/RAM snapshots.")
    args = parser.parse_args(argv)
    print(
        json.dumps(
            run(
                Path(args.output_dir),
                args.iterations,
                args.warmup,
                args.seed,
                args.mode,
                args.export_raw,
                args.profile_resources,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
