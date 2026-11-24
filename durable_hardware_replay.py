"""Process-restart durable nonce claims for authenticated hardware envelopes.

Local SQLite durability is NOT tamper-resistant storage or rollback protection.
The caller must keep the database on trusted storage and fail closed on I/O errors.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time


class DurableNonceStore:
    def __init__(self, path: str, *, max_entries_per_device: int):
        if not path or path == ":memory:" or path.startswith("file:"):
            raise ValueError("durable replay storage requires a filesystem path")
        self._lock = threading.RLock()
        if type(max_entries_per_device) is not int or max_entries_per_device < 1:
            raise ValueError("max_entries_per_device must be a positive integer")
        self._limit = max_entries_per_device
        # A missing/empty file is a first initialization. A nonempty database
        # that has lost its replay tables must never silently start fresh.
        existing_file = os.path.lexists(path)
        if existing_file and not os.path.isfile(path):
            raise ValueError("replay store must be a regular file")
        existing_bytes = os.path.getsize(path) if existing_file else 0
        # An existing zero-length file can be a truncated/rolled-back replay
        # database. Never mistake it for first initialization.
        if existing_file and existing_bytes == 0:
            raise sqlite3.DatabaseError("existing replay database is empty")
        self._db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            # Reject damaged replay state before accepting authenticated inputs.
            # quick_check is not an anti-tamper or anti-rollback mechanism.
            check = self._db.execute("PRAGMA quick_check").fetchall()
            if check != [("ok",)]:
                raise sqlite3.DatabaseError("hardware replay database integrity check failed")
            if existing_bytes:
                tables = {row[0] for row in self._db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
                if not {"nonce_claims", "replay_clock"}.issubset(tables):
                    raise sqlite3.DatabaseError("existing replay database is missing required state tables")
            self._db.execute("CREATE TABLE IF NOT EXISTS nonce_claims (device TEXT NOT NULL, nonce TEXT NOT NULL, expires REAL NOT NULL, PRIMARY KEY(device,nonce))")
            self._db.execute("CREATE TABLE IF NOT EXISTS replay_clock (id INTEGER PRIMARY KEY CHECK(id=1), last_seen REAL NOT NULL)")
        except Exception:
            self._db.close()
            raise

    def claim(self, device: str, nonce: str, *, window_seconds: int) -> str | None:
        """Return stable rejection reason or None; commit before caller acts."""
        with self._lock:
            if type(window_seconds) is not int or window_seconds <= 0:
                raise ValueError("window_seconds must be a positive integer")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                # Sample wall time after acquiring the write lock: a contender
                # must not compare its pre-wait clock against another writer's
                # later persisted high-water mark.
                now = time.time()
                # Persist the maximum observed wall time atomically with each claim.
                # A backwards clock step cannot silently extend an old replay window.
                row = self._db.execute("SELECT last_seen FROM replay_clock WHERE id=1").fetchone()
                if row is not None and now < row[0]:
                    self._db.execute("ROLLBACK")
                    return "HW_REPLAY_CLOCK_ROLLBACK"
                self._db.execute("INSERT INTO replay_clock(id,last_seen) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen", (now,))
                self._db.execute("DELETE FROM nonce_claims WHERE expires <= ?", (now,))
                if self._db.execute("SELECT 1 FROM nonce_claims WHERE device=? AND nonce=?", (device, nonce)).fetchone():
                    self._db.execute("COMMIT")
                    return "HW_REPLAY_DETECTED"
                count = self._db.execute("SELECT COUNT(*) FROM nonce_claims WHERE device=?", (device,)).fetchone()[0]
                if count >= self._limit:
                    self._db.execute("COMMIT")
                    return "HW_REPLAY_CACHE_SATURATED"
                self._db.execute("INSERT INTO nonce_claims(device,nonce,expires) VALUES(?,?,?)", (device, nonce, now + window_seconds))
                self._db.execute("COMMIT")
                return None
            except sqlite3.Error:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._db.close()
