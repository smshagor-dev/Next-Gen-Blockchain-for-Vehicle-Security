"""Process-level adversarial race against production SQLiteNonceStore.

Run: python -m research_contracts.hardware_nonce_race_experiment --workers 16 --rounds 5
No vehicle commands, external network, or hardware are involved.
"""
import argparse
import json
import multiprocessing as mp
import tempfile
from pathlib import Path
from hardware_nonce_store import SQLiteNonceStore


def _worker(db, nonce, barrier, results, index):
    barrier.wait()
    try:
        store = SQLiteNonceStore(db)
        try:
            results[index] = "accepted" if store.claim("pi-bench-1", nonce, ttl_seconds=60) else "replayed"
        finally:
            store.close()
    except Exception as exc:
        results[index] = "error:" + type(exc).__name__


def run_round(workers=16):
    if type(workers) is not int or not 2 <= workers <= 128:
        raise ValueError("workers must be in [2,128]")
    with tempfile.TemporaryDirectory() as directory:
        db = str(Path(directory) / "nonces.sqlite3")
        store = SQLiteNonceStore(db, provision=True)
        store.close()
        ctx = mp.get_context("spawn")
        with ctx.Manager() as manager:
            barrier = manager.Event()
            results = manager.list(["not-run"] * workers)
            nonce = "a" * 32
            children = [ctx.Process(target=_worker, args=(db, nonce, barrier, results, i))
                        for i in range(workers)]
            for child in children:
                child.start()
            barrier.set()
            for child in children:
                child.join(timeout=15)
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=5)
            verifier = SQLiteNonceStore(db)
            try:
                restart_rejected = not verifier.claim("pi-bench-1", nonce, ttl_seconds=60)
            finally:
                verifier.close()
            outcomes = list(results)
            return {
                "workers": workers,
                "accepted": outcomes.count("accepted"),
                "replayed": outcomes.count("replayed"),
                "errors": [x for x in outcomes if x not in ("accepted", "replayed")],
                "exitcodes": [p.exitcode for p in children],
                "restart_rejected": restart_rejected,
            }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 100:
        parser.error("rounds must be in [1,100]")
    records = [dict(round=i, **run_round(args.workers)) for i in range(args.rounds)]
    output = "\n".join(json.dumps(row, sort_keys=True) for row in records) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")
    if any(row["accepted"] != 1 or row["replayed"] != args.workers - 1
           or row["errors"] or not row["restart_rejected"]
           or any(code != 0 for code in row["exitcodes"]) for row in records):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
