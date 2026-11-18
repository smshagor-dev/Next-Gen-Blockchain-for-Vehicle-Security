"""Non-actuating SQLite inbox for experimentally studying durable event admission.

This is NOT an atomic transaction with an external blockchain. A PENDING row
must be reconciled against the ledger after a crash before delivery is retried.
No remote actuation or acknowledgement is performed here.
"""
import hashlib
import json
import sqlite3
from pathlib import Path


class InboxConflict(ValueError):
    pass


class DurableEventInbox:
    def __init__(self, path):
        self.path = str(Path(path))
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS inbox (
            device_id TEXT NOT NULL, nonce TEXT NOT NULL,
            digest TEXT NOT NULL, state TEXT NOT NULL
            CHECK(state IN ('PENDING','COMMITTED')),
            ledger_reference TEXT,
            PRIMARY KEY(device_id, nonce))""")

    @staticmethod
    def digest(payload):
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def admit(self, device_id, nonce, authenticated_payload):
        """Call ONLY after external MAC, identity, freshness and schema verification.

        Returns NEW, PENDING or COMMITTED. A PENDING return is NOT permission
        to blindly append to an external ledger; reconcile by event identity.
        """
        if not isinstance(device_id, str) or not device_id or len(device_id) > 96:
            raise ValueError("invalid device_id")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
            raise ValueError("invalid nonce")
        digest = self.digest(authenticated_payload)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT digest,state FROM inbox WHERE device_id=? AND nonce=?",
                (device_id, nonce)).fetchone()
            if row is None:
                self.db.execute(
                    "INSERT INTO inbox(device_id,nonce,digest,state) VALUES(?,?,?,'PENDING')",
                    (device_id, nonce, digest))
                result = "NEW"
            elif row[0] != digest:
                raise InboxConflict("same identity and nonce with different payload")
            else:
                result = row[1]
            self.db.execute("COMMIT")
            return result
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def mark_committed(self, device_id, nonce, ledger_reference):
        """Record independently VERIFIED ledger inclusion; not blockchain finality."""
        if not isinstance(ledger_reference, str) or not ledger_reference:
            raise ValueError("verified ledger reference required")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT state,ledger_reference FROM inbox WHERE device_id=? AND nonce=?",
                (device_id, nonce)).fetchone()
            if row is None:
                raise KeyError("unknown event")
            if row[0] == "COMMITTED" and row[1] != ledger_reference:
                raise InboxConflict("conflicting ledger reference")
            self.db.execute(
                "UPDATE inbox SET state='COMMITTED',ledger_reference=? WHERE device_id=? AND nonce=?",
                (ledger_reference, device_id, nonce))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def pending(self):
        return self.db.execute(
            "SELECT device_id,nonce,digest FROM inbox WHERE state='PENDING' ORDER BY device_id,nonce"
        ).fetchall()

    def close(self):
        self.db.close()
