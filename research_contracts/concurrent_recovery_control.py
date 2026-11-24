"""Non-actuating SQLite recovery concurrency experiment.

A deterministic model of a durable intent and independent reservation, NOT a
trusted remote anchor. No network, CAN, or physical actuation is performed.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path


def connect(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA busy_timeout=5000")
    return db


def initialize(local: Path, anchor: Path) -> None:
    with connect(local) as db:
        db.execute("CREATE TABLE IF NOT EXISTS intents (nonce TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','complete')))")
    with connect(anchor) as db:
        db.execute("CREATE TABLE IF NOT EXISTS reservations (nonce TEXT PRIMARY KEY, digest TEXT NOT NULL)")


def submit(local: Path, nonce: str, payload: bytes) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    with connect(local) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("INSERT INTO intents VALUES (?, ?, 'pending')", (nonce, digest))
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return digest


def reconcile(local: Path, anchor: Path, nonce: str) -> str:
    """Repair only the same digest; never return an actuation authorization."""
    with connect(local) as db:
        row = db.execute("SELECT digest,state FROM intents WHERE nonce=?", (nonce,)).fetchone()
    if row is None:
        return "missing_intent"
    digest, state = row
    if state == "complete":
        return "already_complete"

    # SQLite serializes concurrent reservations across independent connections.
    with connect(anchor) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            existing = db.execute("SELECT digest FROM reservations WHERE nonce=?", (nonce,)).fetchone()
            if existing is not None and existing[0] != digest:
                db.execute("ROLLBACK")
                return "digest_conflict"
            if existing is None:
                db.execute("INSERT INTO reservations VALUES (?,?)", (nonce, digest))
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise

    with connect(local) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            current = db.execute("SELECT digest,state FROM intents WHERE nonce=?", (nonce,)).fetchone()
            if current is None or current[0] != digest:
                db.execute("ROLLBACK")
                return "intent_changed"
            db.execute("UPDATE intents SET state='complete' WHERE nonce=? AND state='pending'", (nonce,))
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return "reconciled"


def trial(workers: int) -> dict:
    if workers < 1:
        raise ValueError("workers must be positive")
    with tempfile.TemporaryDirectory() as folder:
        local, anchor = Path(folder) / "local.sqlite", Path(folder) / "anchor.sqlite"
        initialize(local, anchor)
        digest = submit(local, "incident-1", b"verified-test-payload")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            outcomes = list(pool.map(lambda _: reconcile(local, anchor, "incident-1"), range(workers)))
        with connect(local) as db:
            state = db.execute("SELECT state FROM intents WHERE nonce='incident-1'").fetchone()[0]
        with connect(anchor) as db:
            reservations = db.execute("SELECT count(*),min(digest) FROM reservations WHERE nonce='incident-1'").fetchone()
        return {"workers": workers, "outcomes": outcomes, "state": state,
                "reservation_count": reservations[0], "digest_matches": reservations[1] == digest}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=16)
    args = parser.parse_args()
    print(json.dumps(trial(args.workers), sort_keys=True))


if __name__ == "__main__":
    main()
