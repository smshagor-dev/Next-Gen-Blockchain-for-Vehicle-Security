"""Reproducible SQLite nonce capacity experiment, not a publication result.

Runs real SQLite claims with a fresh temporary database; captures latency,
RSS (where available), DB/WAL bytes, restart persistence and saturation.
No fabricated data or simulated success counters.
"""
import argparse
import csv
import os
from pathlib import Path
try:
    import resource
except ImportError:
    resource = None  # Windows: RSS unavailable without optional dependencies
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hardware_nonce_store import SQLiteNonceStore, NonceStoreError


def run(output, capacity, samples):
    if capacity < 2 or samples < capacity:
        raise ValueError("samples must be >= capacity >= 2")
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        db_path = os.path.join(directory, "nonce.db")
        store = SQLiteNonceStore(db_path, provision=True, max_claims=capacity)
        try:
            for i in range(samples):
                nonce = f"{i:032x}"
                start = time.perf_counter_ns()
                try:
                    accepted = store.claim("bench-node", nonce, ttl_seconds=30)
                    reason = "accepted" if accepted else "replayed"
                except NonceStoreError:
                    accepted = False
                    reason = "capacity_rejected"
                elapsed = time.perf_counter_ns() - start
                rows.append({
                    "sequence": i, "reason": reason, "accepted": int(accepted),
                    "latency_ns": elapsed,
                    "database_bytes": os.path.getsize(db_path),
                    "wal_bytes": os.path.getsize(db_path + "-wal") if os.path.exists(db_path + "-wal") else 0,
                    "maxrss_platform_units": (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                                              if resource is not None else ''),
                })
        finally:
            store.close()
        recovered = SQLiteNonceStore(db_path, max_claims=capacity)
        try:
            restart_replay_denied = not recovered.claim("bench-node", f"{0:032x}", ttl_seconds=30)
        finally:
            recovered.close()
    if not restart_replay_denied:
        raise AssertionError("restart replay was accepted")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    accepted_latencies = [r["latency_ns"] for r in rows if r["accepted"]]
    return {
        "accepted": sum(r["accepted"] for r in rows),
        "rejected": len(rows) - sum(r["accepted"] for r in rows),
        "median_accepted_latency_ns": statistics.median(accepted_latencies),
        "restart_replay_denied": restart_replay_denied,
        "csv": str(output),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capacity", type=int, default=200)
    parser.add_argument("--samples", type=int, default=300)
    args = parser.parse_args()
    print(run(args.output, args.capacity, args.samples))
