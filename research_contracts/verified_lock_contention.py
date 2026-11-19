"""Independent-process SQLite lock contention and precommit SIGKILL control.

A deliberately bounded busy timeout must expire while a separate process holds
BEGIN IMMEDIATE. This verifies actual conflicting lock acquisition, not merely
the contender announcing that it is about to attempt a lock.
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


def connect(path, timeout=2.0):
    # Do not change journal mode on each worker connection: PRAGMA
    # journal_mode can itself require locks and confound BEGIN contention.
    db = sqlite3.connect(str(path), isolation_level=None, timeout=timeout)
    db.execute("PRAGMA synchronous=FULL")
    return db


def holder(path, locked, release):
    db = connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO events VALUES (?, ?)", ("event-1", "digest-1"))
        locked.set()
        if not release.wait(10):
            raise RuntimeError("release timeout")
        os.kill(os.getpid(), signal.SIGKILL)
    finally:
        db.close()


def contender(path, start, result):
    db = connect(path, timeout=0.2)
    try:
        if not start.wait(10):
            raise RuntimeError("start timeout")
        began = time.monotonic_ns()
        try:
            db.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            elapsed = time.monotonic_ns() - began
            result.put(("locked" if "locked" in str(exc).lower() else "unexpected_error", elapsed))
            return
        else:
            db.execute("ROLLBACK")
            result.put(("unexpected_lock_acquired", time.monotonic_ns() - began))
    finally:
        db.close()


def trial(directory):
    path = Path(directory) / "ledger.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    db = connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE events(identity TEXT PRIMARY KEY, digest TEXT NOT NULL)")
    db.close()
    ctx = mp.get_context("spawn")
    locked, release, start = ctx.Event(), ctx.Event(), ctx.Event()
    results = ctx.Queue()
    first = ctx.Process(target=holder, args=(str(path), locked, release))
    second = ctx.Process(target=contender, args=(str(path), start, results))
    try:
        first.start()
        if not locked.wait(10):
            raise AssertionError("holder failed to acquire write lock")
        second.start()
        start.set()
        # Keep the holder alive until the contender has actually received
        # SQLITE_BUSY. This gives direct, bounded lock-conflict evidence.
        second.join(5)
        if second.is_alive() or second.exitcode != 0:
            raise AssertionError("contender did not complete bounded lock attempt")
        outcome, wait_ns = results.get(timeout=2)
        release.set()
        first.join(5)
        if first.is_alive():
            raise AssertionError("holder did not exit")
        db = connect(path)
        try:
            before = db.execute("SELECT identity,digest FROM events").fetchall()
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO events VALUES (?,?)", ("event-1", "digest-1"))
            db.execute("COMMIT")
            after = db.execute("SELECT identity,digest FROM events").fetchall()
        finally:
            db.close()
        # Require the expected bounded SQLite busy wait, not merely any
        # positive interval (which could be an immediate unrelated failure).
        passed = (outcome == "locked" and wait_ns >= 50_000_000 and
                  first.exitcode == -signal.SIGKILL and before == [] and
                  after == [("event-1", "digest-1")])
        return {"passed": passed, "lock_result": outcome, "wait_ns": wait_ns,
                "holder_exit": first.exitcode, "pre_retry_rows": before,
                "post_retry_rows": after}
    finally:
        release.set()
        for proc in (first, second):
            if proc.pid is not None:
                if proc.is_alive():
                    proc.kill()
                proc.join(timeout=2)


def run(trials=3):
    if not 1 <= trials <= 100:
        raise ValueError("trials must be 1..100")
    with tempfile.TemporaryDirectory() as root:
        observations = [trial(Path(root) / str(i)) for i in range(trials)]
    return {"all_assertions_passed": all(x["passed"] for x in observations),
            "trials": trials, "observations": observations,
            "limitations": "SQLite surrogate lock-conflict control only; no blockchain finality, power-loss, or hardware safety evidence"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=3)
    report = run(parser.parse_args().trials)
    print(json.dumps(report, sort_keys=True))
    if not report["all_assertions_passed"]:
        raise SystemExit(1)
