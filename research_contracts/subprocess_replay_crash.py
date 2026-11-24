"""Non-actuating REAL subprocess crash-boundary experiment (not a vehicle benchmark).

Two independent SQLite stores stand in for local replay state and an anchor.
The 'anchor' is NOT trusted against privileged rollback or host compromise.
A worker exits abruptly with os._exit(73), not an exception or mocked crash.
"""
from __future__ import annotations
import argparse
import csv
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

PROTOCOLS = ("reserve_first", "local_first")
BOUNDARIES = ("after_first_commit", "after_second_commit")

def claim(path: Path, nonce: str) -> bool:
    with sqlite3.connect(path, timeout=5, isolation_level=None) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS claims (nonce TEXT PRIMARY KEY)")
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("INSERT INTO claims VALUES (?)", (nonce,))
            db.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            db.execute("ROLLBACK")
            return False

def worker(local: Path, anchor: Path, protocol: str, boundary: str, nonce: str) -> int:
    if protocol not in PROTOCOLS or boundary not in BOUNDARIES:
        raise ValueError("invalid protocol or boundary")
    order = (anchor, local) if protocol == "reserve_first" else (local, anchor)
    for index, path in enumerate(order):
        if not claim(path, nonce):
            return 2
        if boundary == ("after_first_commit" if index == 0 else "after_second_commit"):
            os._exit(73)
    return 0

def has_claim(path: Path, nonce: str) -> bool:
    if not path.exists():
        return False
    with sqlite3.connect(path) as db:
        return bool(db.execute("SELECT 1 FROM claims WHERE nonce=?", (nonce,)).fetchone())

def run_case(protocol: str, boundary: str, directory: Path) -> dict:
    local, anchor = directory / "local.sqlite", directory / "anchor.sqlite"
    nonce = "nonce-crash-control"
    cmd = [sys.executable, "-m", "research_contracts.subprocess_replay_crash",
           "--worker", "--local", str(local), "--anchor", str(anchor),
           "--protocol", protocol, "--boundary", boundary, "--nonce", nonce]
    crashed = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if crashed.returncode != 73:
        raise RuntimeError(f"expected abrupt exit 73, got {crashed.returncode}: {crashed.stderr}")
    before_local, before_anchor = has_claim(local, nonce), has_claim(anchor, nonce)
    retry = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    # A duplicate on the first store returns 2 without reaching the second store.
    if retry.returncode != 2:
        raise RuntimeError(f"expected duplicate rejection 2, got {retry.returncode}: {retry.stderr}")
    return dict(protocol=protocol, crash_boundary=boundary,
                local_committed=int(before_local), anchor_committed=int(before_anchor),
                retry_rejected=int(retry.returncode == 2),
                inconsistent_after_crash=int(before_local != before_anchor))

def experiment():
    for protocol in PROTOCOLS:
        for boundary in BOUNDARIES:
            with tempfile.TemporaryDirectory(prefix="v2x-crash-") as temp:
                yield run_case(protocol, boundary, Path(temp))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--local", type=Path)
    parser.add_argument("--anchor", type=Path)
    parser.add_argument("--protocol", choices=PROTOCOLS)
    parser.add_argument("--boundary", choices=BOUNDARIES)
    parser.add_argument("--nonce", default="nonce-crash-control")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.worker:
        if args.local is None or args.anchor is None or args.protocol is None or args.boundary is None:
            parser.error("worker requires both stores, protocol and boundary")
        return worker(args.local, args.anchor, args.protocol, args.boundary, args.nonce)
    rows = list(experiment())
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    for row in rows:
        print(row)
    return 0

if __name__ == "__main__":
    sys.exit(main())
