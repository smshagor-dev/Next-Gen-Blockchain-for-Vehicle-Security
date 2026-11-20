"""Process-restart durable nonce claims for authenticated hardware envelopes.

Local SQLite durability is NOT tamper-resistant storage or rollback protection.
The caller must keep the database on trusted storage and fail closed on I/O errors.
"""
from __future__ import annotations

import sqlite3
import threading
import time


class DurableNonceStore:
    def __init__(self, path: str, *, max_entries_per_device: int):
        if not path or path == ":memory:" or path.startswith("file:"):
            raise ValueError("durable replay storage requires a filesystem path")
        self._lock = threading.RLock()
        self._limit = max_entries_per_device
        self._db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("CREATE TABLE IF NOT EXISTS nonce_claims (device TEXT NOT NULL, nonce TEXT NOT NULL, expires REAL NOT NULL, PRIMARY KEY(device,nonce))")
        except Exception:
            self._db.close()
            raise

    def claim(self, device: str, nonce: str, *, window_seconds: int) -> str | None:
        """Return stable rejection reason or None; commit before caller acts."""
        with self._lock:
            now = time.time()
            try:
                self._db.execute("BEGIN IMMEDIATE")
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
