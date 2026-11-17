"""Crash-persistent authenticated nonce claims for a single bridge process.

This is local replay durability, not a monotonic hardware counter, consensus
finality, or protection from privileged restoration of an older disk snapshot.
"""
import os
import sqlite3
import threading
import time
import math

DEFAULT_MAX_NONCE_CLAIMS = 100000


class NonceStoreError(RuntimeError):
    pass


class SQLiteNonceStore:
    def __init__(self, path, *, provision=False, clock=None, max_claims=DEFAULT_MAX_NONCE_CLAIMS):
        if not isinstance(path, (str, os.PathLike)) or not os.fspath(path):
            raise ValueError("persistent nonce database path required")
        if type(provision) is not bool:
            raise ValueError("provision must be bool")
        if type(max_claims) is not int or not 1 <= max_claims <= 1000000:
            raise ValueError("max_claims must be an integer within [1, 1000000]")
        self._max_claims = max_claims
        self._clock = clock or time.time
        self._lock = threading.RLock()
        exists = os.path.exists(path)
        if provision and exists:
            # Never recreate an existing database after a crash or corruption.
            # Provisioning is a one-time operation, not a recovery fallback.
            raise NonceStoreError("nonce database already exists; provisioning denied")
        if not provision and (not os.path.isfile(path) or os.stat(path).st_size == 0):
            raise NonceStoreError("nonce database missing; explicit provisioning required")
        self._db = sqlite3.connect(path, timeout=5.0, isolation_level=None, check_same_thread=False)
        try:
            mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            self._db.execute("PRAGMA synchronous=FULL")
            if mode.lower() != "wal" or self._db.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise NonceStoreError("durable SQLite settings unavailable")
            if provision:
                self._db.execute("CREATE TABLE IF NOT EXISTS nonce_claims "
                                 "(device TEXT NOT NULL, nonce TEXT NOT NULL, expires REAL NOT NULL, "
                                 "PRIMARY KEY(device, nonce))")
            else:
                integrity = self._db.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise NonceStoreError("nonce database integrity failure")
                columns = self._db.execute("PRAGMA table_info(nonce_claims)").fetchall()
                if [(c[1], c[2].upper(), c[5]) for c in columns] != [
                    ("device", "TEXT", 1), ("nonce", "TEXT", 2), ("expires", "REAL", 0)
                ]:
                    raise NonceStoreError("nonce schema missing or incompatible")
        except BaseException:
            self._db.close()
            raise

    def claim(self, device, nonce, *, ttl_seconds):
        if (type(device) is not str or not 1 <= len(device) <= 96
                or type(nonce) is not str or not 32 <= len(nonce) <= 128
                or type(ttl_seconds) not in (int, float) or not 1 <= ttl_seconds <= 600):
            raise ValueError("invalid nonce claim")
        with self._lock:
            now = float(self._clock())
            if not math.isfinite(now):
                raise NonceStoreError("invalid local clock; nonce admission denied")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                # Never delete an existing nonce before testing it: an expired
                # claim may still be relevant if the local clock moves backward.
                found = self._db.execute(
                    "SELECT 1 FROM nonce_claims WHERE device=? AND nonce=?",
                    (device, nonce),
                ).fetchone()
                if found is not None:
                    self._db.execute("ROLLBACK")
                    return False
                count = self._db.execute("SELECT COUNT(*) FROM nonce_claims").fetchone()[0]
                if count >= self._max_claims:
                    raise NonceStoreError("nonce store capacity exhausted; admission denied")
                self._db.execute(
                    "INSERT INTO nonce_claims(device,nonce,expires) VALUES(?,?,?)",
                    (device, nonce, now + ttl_seconds),
                )
                self._db.execute("COMMIT")
                return True
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def close(self):
        with self._lock:
            self._db.close()
