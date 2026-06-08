"""Deterministic communication-volume scalability analysis for OmniGuard V2X.

This runner computes analytical message-volume growth for prototype network
topologies. It is not a distributed runtime benchmark and does not report
measured latency, throughput, CPU, RAM, or consensus duration.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

try:
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_csv, write_json
except ModuleNotFoundError:
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from experiments.common import DEFAULT_REPORT_DIR, artifact_manifest, ensure_dir, utc_now, write_csv, write_json


NODE_COUNTS = [10, 50, 100, 500, 1000, 5000, 10000]
TOPOLOGIES = ["full-mesh", "gossip-fanout", "committee"]
METRICS = [
    "total_messages",
    "messages_per_round",
    "average_messages_per_node",
    "theoretical_complexity",
]


@dataclass(frozen=True)
class ScalabilityConfig:
    nodes: int
    topology: str = "full-mesh"
    rounds: int = 10
    fanout: int = 8
    committee_size: int = 50
    seed: int = 0


def _parse_node_counts(value: str | Sequence[int] | None) -> List[int]:
    if value is None:
        return list(NODE_COUNTS)
    if isinstance(value, str):
        parts = [part.strip() for part in value.replace(",", " ").split() if part.strip()]
        return [int(part) for part in parts]
    return [int(v) for v in value]


def build_plan(
    node_counts: Sequence[int] = NODE_COUNTS,
    topology: str = "full-mesh",
    rounds: int = 10,
    fanout: int = 8,
    committee_size: int = 50,
    seed: int = 0,
) -> List[ScalabilityConfig]:
    return [
        ScalabilityConfig(
            nodes=int(nodes),
            topology=str(topology),
            rounds=int(rounds),
            fanout=int(fanout),
            committee_size=int(committee_size),
            seed=int(seed),
        )
        for nodes in node_counts
    ]


def _messages_per_round(n: int, topology: str, fanout: int, committee_size: int) -> tuple[int, str, int]:
    if n < 1:
        raise ValueError("node counts must be positive")
    if topology == "full-mesh":
        return n * (n - 1), "O(n^2)", n
    if topology == "gossip-fanout":
        return n * min(int(fanout), n - 1), "O(n*fanout)", n
    if topology == "committee":
        active_validators = min(int(committee_size), n)
        return active_validators * (active_validators - 1), "O(c^2)", active_validators
    raise ValueError(f"Unsupported topology: {topology}")


def row_from_config(cfg: ScalabilityConfig) -> dict:
    messages_per_round, complexity, active_validators = _messages_per_round(
        cfg.nodes,
        cfg.topology,
        cfg.fanout,
        cfg.committee_size,
    )
    total_messages = messages_per_round * cfg.rounds
    return {
        "topology": cfg.topology,
        "node_count": cfg.nodes,
        "rounds": cfg.rounds,
        "fanout": cfg.fanout,
        "committee_size": cfg.committee_size,
        "active_validators": active_validators,
        "messages_per_round": messages_per_round,
        "total_messages": total_messages,
        "average_messages_per_node": round(total_messages / cfg.nodes, 6),
        "theoretical_complexity": complexity,
        "measured_runtime_benchmark": False,
        "seed": cfg.seed,
    }


def rows_from_plan(plan: Sequence[ScalabilityConfig]) -> List[dict]:
    return [row_from_config(cfg) for cfg in plan]


def _write_scalability_markdown(path: Path, summary: dict, rows: Sequence[dict]) -> Path:
    ensure_dir(path.parent)
    lines = [
        "# Scalability Communication-Volume Analysis",
        "",
        "This is communication-volume simulation/analysis, not a distributed runtime benchmark.",
        "It validates expected message-count growth only; it does not claim measured latency, throughput, CPU, RAM, or consensus duration.",
        "",
        "## Formulas",
        "",
        "- `full-mesh`: `messages_per_round = n * (n - 1)`; complexity `O(n^2)`.",
        "- `gossip-fanout`: `messages_per_round = n * min(fanout, n - 1)`; complexity `O(n*fanout)`.",
        "- `committee`: `active_validators = min(committee_size, n)`, `messages_per_round = c * (c - 1)`; complexity `O(c^2)`.",
        "",
        "## Summary",
        "",
    ]
    for key, value in summary.items():
        if key != "artifacts":
            lines.append(f"- `{key}`: `{value}`")
    fields = [
        "topology",
        "node_count",
        "rounds",
        "messages_per_round",
        "total_messages",
        "average_messages_per_node",
        "theoretical_complexity",
        "measured_runtime_benchmark",
    ]
    lines.extend(["", "## Results", ""])
    lines.append("| " + " | ".join(fields) + " |")
    lines.append("| " + " | ".join(["---"] * len(fields)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_scalability_plot(path: Path, rows: Sequence[dict]) -> Path:
    ensure_dir(path.parent)
    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(9, 5))
        labels = [int(row["node_count"]) for row in rows]
        values = [int(row["messages_per_round"]) for row in rows]
        ax.plot(labels, values, marker="o", color="#2f80ed")
        ax.set_xlabel("node count")
        ax.set_ylabel("messages per round")
        ax.set_title("Communication-Volume Analysis")
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
    node_counts: Sequence[int] | None = None,
    rounds: int = 10,
    topology: str = "full-mesh",
    fanout: int = 8,
    committee_size: int = 50,
    seed: int = 0,
) -> dict:
    ensure_dir(output_dir)
    counts = _parse_node_counts(node_counts)
    plan = build_plan(counts, topology=topology, rounds=rounds, fanout=fanout, committee_size=committee_size, seed=seed)
    rows = rows_from_plan(plan)
    summary = {
        "experiment": "scalability",
        "status": "communication_volume_analysis_only",
        "created_at": utc_now(),
        "node_counts": ",".join(str(n) for n in counts),
        "rounds": int(rounds),
        "topology": topology,
        "fanout": int(fanout),
        "committee_size": int(committee_size),
        "metrics": ",".join(METRICS),
        "measured_runtime_benchmark": False,
        "seed": int(seed),
    }
    fields = [
        "topology",
        "node_count",
        "rounds",
        "fanout",
        "committee_size",
        "active_validators",
        "messages_per_round",
        "total_messages",
        "average_messages_per_node",
        "theoretical_complexity",
        "measured_runtime_benchmark",
        "seed",
    ]
    csv_path = write_csv(output_dir / "scalability_results.csv", rows, fields)
    json_path = write_json(output_dir / "scalability_results.json", {**summary, "rows": rows})
    md_path = _write_scalability_markdown(output_dir / "scalability_report.md", summary, rows)
    png_path = _write_scalability_plot(output_dir / "scalability_plot.png", rows)
    return {**summary, "rows": rows, "artifacts": artifact_manifest([csv_path, json_path, md_path, png_path])}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run OmniGuard V2X communication-volume scalability analysis.")
    parser.add_argument("--node-counts", default=",".join(str(n) for n in NODE_COUNTS))
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--topology", default="full-mesh", choices=TOPOLOGIES)
    parser.add_argument("--fanout", type=int, default=8)
    parser.add_argument("--committee-size", type=int, default=50)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output-dir", default=str(DEFAULT_REPORT_DIR / "scalability"))
    args = parser.parse_args(argv)
    payload = run(
        Path(args.output_dir),
        node_counts=_parse_node_counts(args.node_counts),
        rounds=args.rounds,
        topology=args.topology,
        fanout=args.fanout,
        committee_size=args.committee_size,
        seed=args.seed,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
