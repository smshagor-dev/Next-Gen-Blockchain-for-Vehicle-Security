"""Research-only durable command replay gate; never authorizes physical actuation.

SQLite commits each nonce before a caller may emit a simulated acknowledgment.
This is a local crash-consistency property, not rollback-resistant storage.
"""
from __future__ import annotations
import sqlite3
from pathlib import Path


class DurableReplayError(RuntimeError):
    pass


class DurableCommandReplayGate:
    def __init__(self, path: str, *, timeout: float = 1.0):
        if path == ':memory:':
            raise ValueError('Durable replay gate requires persistent storage')
        self.path = Path(path)
        if not self.path.parent.is_dir():
            raise ValueError('Replay database parent must already exist')
        self.db = sqlite3.connect(str(self.path), timeout=timeout, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS consumed (device TEXT NOT NULL, nonce TEXT NOT NULL, PRIMARY KEY(device, nonce))')

    def claim_verified(self, *, device_id: str, nonce: str) -> bool:
        """Only call after MAC, identity, freshness and semantics are verified.

        Never delete consumed nonces automatically: wall-clock rollback or a
        restored envelope must not make an old command acceptable again.
        """
        if not device_id or not nonce or len(device_id) > 96 or len(nonce) > 128:
            raise ValueError('Invalid replay identity')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('INSERT INTO consumed(device, nonce) VALUES (?, ?)', (device_id, nonce))
            self.db.execute('COMMIT')
            return True
        except sqlite3.IntegrityError:
            self.db.execute('ROLLBACK')
            return False
        except Exception:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise

    def close(self):
        self.db.close()
