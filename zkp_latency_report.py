# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Generate latency summary from logs/zkp_latency.jsonl.
"""

import json
import os
import statistics

from env_config import load_project_env_once, get_env

load_project_env_once()


def main():
    path = get_env("SMARTCAR_ZKP_LATENCY_LOG", "logs/zkp_latency.jsonl")
    if not os.path.exists(path):
        print(f"No latency log found: {path}")
        return

    buckets = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            op = rec.get("operation", "unknown")
            phase = rec.get("phase", "unknown")
            ms = float(rec.get("latency_ms", 0.0))
            key = f"{op}:{phase}"
            buckets.setdefault(key, []).append(ms)

    print(f"ZKP Latency Report ({path})")
    for key in sorted(buckets.keys()):
        vals = buckets[key]
        avg = statistics.mean(vals)
        p95 = sorted(vals)[int(max(0, min(len(vals)-1, round(len(vals) * 0.95) - 1)))]
        print(f"- {key} count={len(vals)} avg_ms={avg:.4f} p95_ms={p95:.4f} min_ms={min(vals):.4f} max_ms={max(vals):.4f}")


if __name__ == "__main__":
    main()

