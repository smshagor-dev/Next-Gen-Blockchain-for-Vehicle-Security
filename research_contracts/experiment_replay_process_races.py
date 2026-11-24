"""Independent process-level replay-admission fault experiment (engineering pilot only).

Run: python research_contracts/experiment_replay_process_races.py --trials 5 --workers 8
No hardware, blockchain finality, or publishable V2X detection claim.
"""
import argparse
import csv
import multiprocessing as mp
import os
from pathlib import Path
import sqlite3
import tempfile
import time

from sqlite_atomic_replay import SQLiteAtomicReplayGate


def worker(path, start, output, node, sequence):
    start.wait()
    begin = time.perf_counter_ns()
    try:
        gate = SQLiteAtomicReplayGate(path, timeout=10)
        try:
            admitted = gate.admit_authenticated(node, sequence, authenticated=True)
        finally:
            gate.close()
        output.put((int(admitted), "", time.perf_counter_ns() - begin))
    except Exception as exc:
        output.put((0, type(exc).__name__, time.perf_counter_ns() - begin))


def trial(ctx, path, workers, scenario):
    start = ctx.Event()
    output = ctx.Queue()
    processes = [
        ctx.Process(
            target=worker,
            args=(path, start, output,
                  "shared" if scenario == "same_nonce" else f"node-{i}",
                  1),
        )
        for i in range(workers)
    ]
    # Initialize schema before launching contending processes.
    gate = SQLiteAtomicReplayGate(path)
    gate.close()
    for process in processes:
        process.start()
    start_ns = time.perf_counter_ns()
    start.set()
    results = [output.get(timeout=45) for _ in processes]
    for process in processes:
        process.join(timeout=10)
        if process.is_alive():
            process.terminate()
            process.join()
            raise RuntimeError("worker did not terminate")
        if process.exitcode != 0:
            raise RuntimeError(f"worker exited {process.exitcode}")
    admitted = sum(row[0] for row in results)
    errors = [row[1] for row in results if row[1]]
    expected = 1 if scenario == "same_nonce" else workers
    # Verify durable state independently after all workers have exited.
    with sqlite3.connect(path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM replay_highwater").fetchone()[0]
    if admitted != expected or count != expected or errors:
        raise AssertionError(
            f"{scenario}: admitted={admitted}, rows={count}, "
            f"expected={expected}, errors={errors}"
        )
    return {
        "scenario": scenario,
        "workers": workers,
        "admitted": admitted,
        "rejected": workers - admitted,
        "sqlite_errors": len(errors),
        "elapsed_ms": (time.perf_counter_ns() - start_ns) / 1e6,
        "max_worker_ms": max(row[2] for row in results) / 1e6,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    if not 1 <= args.trials <= 100 or not 2 <= args.workers <= 64:
        parser.error("trials must be 1..100 and workers 2..64")
    ctx = mp.get_context("spawn")
    rows = []
    for repetition in range(args.trials):
        for scenario in ("same_nonce", "distinct_nodes"):
            with tempfile.TemporaryDirectory() as directory:
                result = trial(ctx, os.path.join(directory, "replay.sqlite"),
                               args.workers, scenario)
                result["trial"] = repetition
                rows.append(result)
                print(result, flush=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


if __name__ == "__main__":
    main()
