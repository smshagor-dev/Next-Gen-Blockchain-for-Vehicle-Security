"""Controlled replay rollback experiment, not publishable V2X evidence.

Demonstrates the boundary of SQLite FULL/WAL durability: restoring an older,
otherwise valid database snapshot can roll back replay high-water. No attacker
controls an ECU, and no physical hardware is exercised.
"""
import csv
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlite_atomic_replay import SQLiteAtomicReplayGate


def run_trial(trial):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "replay.sqlite")
        backup = os.path.join(tmp, "snapshot.sqlite")
        gate = SQLiteAtomicReplayGate(path)
        try:
            assert gate.admit_authenticated("enrolled-node", 10, authenticated=True)
            # SQLite online backup captures a consistent older committed state,
            # not a naive copy of a live WAL database.
            with __import__("sqlite3").connect(backup) as destination:
                gate.connection.backup(destination)
            assert gate.admit_authenticated("enrolled-node", 11, authenticated=True)
            normal_replay_accepted = gate.admit_authenticated(
                "enrolled-node", 11, authenticated=True)
            assert normal_replay_accepted is False
        finally:
            gate.close()

        # Offline rollback of the database file, representing privileged
        # storage restoration. This is NOT a power-loss or network attack.
        shutil.copyfile(backup, path)
        for suffix in ("-wal", "-shm"):
            stale = path + suffix
            if os.path.exists(stale):
                os.unlink(stale)
        recovered = SQLiteAtomicReplayGate(path, require_existing=True)
        try:
            rollback_replay_accepted = recovered.admit_authenticated(
                "enrolled-node", 11, authenticated=True)
            assert rollback_replay_accepted is True, (
                "experiment assumption changed: inspect rollback protection")
        finally:
            recovered.close()
        return {
            "trial": trial,
            "policy": "sqlite_full_wal_without_external_rollback_anchor",
            "normal_replay_accepted": int(normal_replay_accepted),
            "rollback_replay_accepted": int(rollback_replay_accepted),
            "snapshot_highwater": 10,
            "pre_restore_highwater": 11,
            "claim_scope": "storage_rollback_counterexample_only",
        }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 1 <= args.trials <= 1000:
        parser.error("--trials must be between 1 and 1000")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = [run_trial(i) for i in range(args.trials)]
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("Executed", len(rows), "controlled storage rollback trials; CSV:", output)
    print("This counterexample is not a statistical attack-detection result.")


if __name__ == "__main__":
    main()
