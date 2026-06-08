"""Run all OmniGuard V2X validation scaffold generators."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

try:
    from experiments.adversarial.run_adversarial_detection import run as run_adversarial
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_json
    from experiments.fl.run_fl_experiments import run as run_fl
    from experiments.latency.run_latency_benchmarks import run as run_latency
    from experiments.scalability.run_scalability import run as run_scalability
except ModuleNotFoundError:
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[1]))
    from experiments.adversarial.run_adversarial_detection import run as run_adversarial
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_json
    from experiments.fl.run_fl_experiments import run as run_fl
    from experiments.latency.run_latency_benchmarks import run as run_latency
    from experiments.scalability.run_scalability import run as run_scalability


def run_all(output_dir: Path) -> dict:
    ensure_dir(output_dir)
    results = {
        "scalability": run_scalability(output_dir / "scalability"),
        "fl": run_fl(output_dir / "fl"),
        "adversarial": run_adversarial(output_dir / "adversarial"),
        "latency": run_latency(output_dir / "latency", iterations=10, warmup=1),
    }
    manifest = {
        "status": "framework_only_no_benchmark_results",
        "created_at": utc_now(),
        "experiments": results,
        "artifacts": artifact_manifest([Path(p) for r in results.values() for p in r.get("artifacts", [])]),
        "todo": [
            "Connect real distributed scalability deployment harness.",
            "Connect real FL datasets/models and attack implementations.",
            "Connect labeled adversarial detection datasets.",
            "Run repeated cold/warm latency benchmarks with raw logs.",
        ],
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate all OmniGuard V2X validation scaffold reports.")
    parser.add_argument("--output-dir", default=str(DEFAULT_REPORT_DIR))
    args = parser.parse_args(argv)
    print(json.dumps(run_all(Path(args.output_dir)), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
