"""Non-actuating SQLite two-store recovery experiment; NOT a trusted authority.

A durable local intent is recorded before reserving the independent store.
Recovery requires exact event digest agreement; it never issues commands.
The stores are two files on one host, not a Byzantine-resilient anchor.
"""
import hashlib
import sqlite3
from pathlib import Path

class RecoveryConflict(RuntimeError):
    pass

def digest_event(payload: bytes) -> str:
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("nonempty bytes required")
    return hashlib.sha256(b"v2x-recovery-v1\x00" + payload).hexdigest()

class RecoveryExperiment:
    def __init__(self, local_path, anchor_path):
        if Path(local_path).resolve() == Path(anchor_path).resolve():
            raise ValueError("stores must have distinct paths")
        self.local = sqlite3.connect(local_path, isolation_level='DEFERRED')
        self.anchor = sqlite3.connect(anchor_path, isolation_level='DEFERRED')
        for db in (self.local, self.anchor):
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
        self.local.execute("CREATE TABLE IF NOT EXISTS intents (event_id TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','complete')))")
        self.anchor.execute("CREATE TABLE IF NOT EXISTS reservations (event_id TEXT PRIMARY KEY, digest TEXT NOT NULL)")

    def close(self):
        self.local.close()
        self.anchor.close()

    def stage(self, event_id: str, payload: bytes):
        if not event_id or not isinstance(event_id, str):
            raise ValueError("event_id required")
        d = digest_event(payload)
        with self.local:
            row = self.local.execute("SELECT digest FROM intents WHERE event_id=?", (event_id,)).fetchone()
            if row and row[0] != d:
                raise RecoveryConflict("local event-id equivocation")
            if not row:
                self.local.execute("INSERT INTO intents VALUES (?,?,'pending')", (event_id,d))
        return d

    def reconcile(self, event_id: str, *, anchor_available=True):
        """Repair an existing intent only; never authorize or dispatch actuation."""
        row = self.local.execute("SELECT digest,state FROM intents WHERE event_id=?", (event_id,)).fetchone()
        if row is None:
            raise RecoveryConflict("missing local intent")
        d, state = row
        if not anchor_available:
            return "pending"
        with self.anchor:
            anchor_row = self.anchor.execute("SELECT digest FROM reservations WHERE event_id=?", (event_id,)).fetchone()
            if anchor_row and anchor_row[0] != d:
                raise RecoveryConflict("anchor digest mismatch")
            if anchor_row is None:
                self.anchor.execute("INSERT INTO reservations VALUES (?,?)", (event_id,d))
        with self.local:
            current = self.local.execute("SELECT digest FROM intents WHERE event_id=?", (event_id,)).fetchone()
            if current is None or current[0] != d:
                raise RecoveryConflict("local intent changed during reconciliation")
            self.local.execute("UPDATE intents SET state='complete' WHERE event_id=? AND digest=?", (event_id,d))
        return "complete"

    def state(self, event_id):
        row = self.local.execute("SELECT state FROM intents WHERE event_id=?", (event_id,)).fetchone()
        return row[0] if row else None
