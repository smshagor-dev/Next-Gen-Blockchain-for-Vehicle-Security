"""Independent-process SQLite precommit kill and surviving-writer timing control.

Surrogate only: no blockchain finality, physical power-loss or hardware safety claims.
"""
import argparse
import json
import multiprocessing as mp
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import time

def _connect(path):
    return sqlite3.connect(path, timeout=5, isolation_level=None)

def _holder(path, ready, release):
    db = _connect(path)
    db.execute("BEGIN IMMEDIATE")
    db.execute("INSERT INTO events VALUES ('same-event','victim')")
    ready.set()
    if not release.wait(10):
        os._exit(71)
    os.kill(os.getpid(), signal.SIGKILL)

def _contender(path, start, attempting, result):
    db = _connect(path)
    if not start.wait(10):
        os._exit(72)
    began = time.monotonic_ns()
    attempting.set()
    try:
        db.execute("BEGIN IMMEDIATE")
        acquired = time.monotonic_ns()
        rows = db.execute("SELECT identity,digest FROM events").fetchall()
        if not rows:
            db.execute("INSERT INTO events VALUES ('same-event','survivor')")
        db.execute("COMMIT")
        result.put({"status":"committed","wait_ns":acquired-began,"rows_seen":rows})
    except Exception as exc:
        result.put({"status":"error","error":type(exc).__name__})
    finally:
        db.close()

def trial(directory, hold_ms=100):
    if not 20 <= hold_ms <= 2000:
        raise ValueError("hold_ms must be 20..2000")
    Path(directory).mkdir(parents=True, exist_ok=True)
    path = str(Path(directory) / "ledger.sqlite")
    db = _connect(path)
    db.execute("CREATE TABLE events(identity TEXT PRIMARY KEY,digest TEXT NOT NULL)")
    db.close()
    ctx = mp.get_context("spawn")
    ready, start, attempting, release = [ctx.Event() for _ in range(4)]
    result = ctx.Queue()
    victim = ctx.Process(target=_holder, args=(path,ready,release))
    survivor = ctx.Process(target=_contender,args=(path,start,attempting,result))
    try:
        victim.start()
        if not ready.wait(10):
            raise RuntimeError("victim readiness timeout")
        survivor.start()
        start.set()
        if not attempting.wait(10):
            raise RuntimeError("survivor readiness timeout")
        # This is scheduling exposure, not independent proof of SQLITE_BUSY.
        time.sleep(hold_ms / 1000)
        if not victim.is_alive():
            raise RuntimeError("victim exited before injection")
        release.set()
        victim.join(5)
        survivor.join(8)
        if victim.is_alive() or survivor.is_alive():
            raise RuntimeError("worker timeout")
        observation = result.get(timeout=2) if survivor.exitcode == 0 else {"status":"worker_exit"}
        db = _connect(path)
        try:
            rows = db.execute("SELECT identity,digest FROM events").fetchall()
        finally:
            db.close()
        observation.update({"victim_exit":victim.exitcode,"survivor_exit":survivor.exitcode,
                            "final_rows":rows,"hold_ms":hold_ms})
        observation["passed"] = (victim.exitcode == -signal.SIGKILL and
            survivor.exitcode == 0 and observation["status"] == "committed" and
            observation["rows_seen"] == [] and rows == [("same-event","survivor")])
        return observation
    finally:
        release.set()
        for process in (victim,survivor):
            if process.pid is not None:
                if process.is_alive():
                    process.kill()
                process.join(timeout=2)
        result.close()

def run(trials=3, hold_ms=100):
    if not 1 <= trials <= 100:
        raise ValueError("trials must be 1..100")
    with tempfile.TemporaryDirectory() as root:
        observations = [trial(Path(root)/str(i),hold_ms) for i in range(trials)]
    return {"passed":all(item["passed"] for item in observations),
            "observations":observations,
            "limitations":"Local SQLite surrogate; no independent busy-handler proof, consensus finality, power loss or physical safety"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials",type=int,default=3)
    parser.add_argument("--hold-ms",type=int,default=100)
    args = parser.parse_args()
    report = run(args.trials,args.hold_ms)
    print(json.dumps(report,sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)
