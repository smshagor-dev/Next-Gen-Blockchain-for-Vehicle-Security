"""Process-overlap precommit SIGKILL control; SQLite surrogate, never hardware."""
import argparse
import json
import multiprocessing as mp
import os
from pathlib import Path
import signal
import sqlite3
import tempfile

def connect(path):
    db = sqlite3.connect(str(path), isolation_level=None, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db

def victim(path, inserted, release):
    db = connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO events(identity,digest) VALUES (?,?)", ("event-1","digest-1"))
        inserted.set()
        if not release.wait(10):
            raise RuntimeError("victim release timeout")
        os.kill(os.getpid(), signal.SIGKILL)
    finally:
        db.close()

def contender(path, attempting, outcome):
    db = connect(path)
    try:
        attempting.set()
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT OR IGNORE INTO events(identity,digest) VALUES (?,?)", ("event-1","digest-1"))
        db.execute("COMMIT")
        outcome.put("committed")
    except Exception as exc:
        outcome.put(type(exc).__name__)
    finally:
        db.close()

def trial(directory):
    path = Path(directory) / "ledger.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    db = connect(path)
    db.execute("CREATE TABLE events(identity TEXT PRIMARY KEY,digest TEXT NOT NULL)")
    db.close()
    ctx = mp.get_context("spawn")
    inserted, release, attempting = ctx.Event(), ctx.Event(), ctx.Event()
    outcome = ctx.Queue()
    first = ctx.Process(target=victim, args=(str(path),inserted,release))
    second = ctx.Process(target=contender, args=(str(path),attempting,outcome))
    try:
        first.start()
        if not inserted.wait(10):
            raise AssertionError("victim did not insert")
        second.start()
        if not attempting.wait(10):
            raise AssertionError("contender did not attempt lock")
        # Signal occurs before BEGIN IMMEDIATE; actual lock-wait overlap is
        # not independently observed. Do not claim measured lock contention.
        release.set()
        first.join(10)
        second.join(10)
        if first.is_alive() or second.is_alive():
            raise AssertionError("worker timeout")
        result = outcome.get(timeout=2)
        db = connect(path)
        try:
            rows = db.execute("SELECT identity,digest FROM events").fetchall()
        finally:
            db.close()
        passed = (first.exitcode == -signal.SIGKILL and second.exitcode == 0
                  and result == "committed" and rows == [("event-1","digest-1")])
        return {"passed":passed,"victim_exit":first.exitcode,
                "contender_exit":second.exitcode,"contender_result":result,"rows":rows}
    finally:
        release.set()
        for process in (first,second):
            if process.pid is not None:
                if process.is_alive():
                    process.kill()
                process.join(timeout=2)

def run(trials=3):
    if not 1 <= trials <= 100:
        raise ValueError("trials must be 1..100")
    with tempfile.TemporaryDirectory() as root:
        observations = [trial(Path(root)/str(i)) for i in range(trials)]
    return {"all_assertions_passed":all(x["passed"] for x in observations),
            "trials":trials,"observations":observations,
            "limitations":"SQLite surrogate; lock-wait not independently observed; no blockchain finality or power-cut evidence"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials",type=int,default=3)
    result = run(parser.parse_args().trials)
    print(json.dumps(result,sort_keys=True))
    if not result["all_assertions_passed"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
