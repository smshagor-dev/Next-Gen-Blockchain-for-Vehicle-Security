"""SQLite-backed atomic replay high-water admission for simulation research.

No physical actuator, distributed finality, or blockchain consensus is implied.
Each batch is a single SQLite transaction. One writer is serialized by SQLite.
"""
import sqlite3
import threading
import math
import itertools

MAX_BATCH_ENTRIES = 4096
MAX_NODE_ID_BYTES = 128


class ReplayStoreError(RuntimeError):
    pass


class SQLiteAtomicReplayGate:
    def __init__(self, path, timeout=5.0):
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("timeout must be within (0, 60] seconds")
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(path, timeout=timeout, isolation_level=None, check_same_thread=False)
        try:
            self.connection.execute("PRAGMA busy_timeout = %d" % int(timeout * 1000))
            if self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                raise ReplayStoreError("WAL journal unavailable")
            self.connection.execute("PRAGMA synchronous=FULL")
            if self.connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise ReplayStoreError("FULL synchronous mode unavailable")
        except BaseException:
            self.connection.close()
            raise
        self.connection.execute("CREATE TABLE IF NOT EXISTS replay_highwater (node TEXT PRIMARY KEY, seq INTEGER NOT NULL CHECK(seq >= 0))")

    def close(self):
        with self._lock:
            self.connection.close()

    def admit_authenticated_batch(self, entries, authenticated=False):
        """Return True iff ALL authenticated (node, seq) entries advance high-water.

        False means no entry was admitted. On SQL failure rollback and propagate.
        The caller must not expose events until this function returns True.
        """
        if authenticated is not True:
            raise ValueError("authentication required")
        # Bound generator consumption before opening a transaction. A malicious
        # authenticated peer must not force unbounded replay batch allocation.
        # The extra element distinguishes exactly-at-limit from over-limit.
        entries = list(itertools.islice(iter(entries), MAX_BATCH_ENTRIES + 1))
        if len(entries) > MAX_BATCH_ENTRIES:
            raise ValueError("replay batch exceeds maximum entries")
        for node, seq in entries:
            if (not isinstance(node, str) or not node or len(node.encode("utf-8")) > MAX_NODE_ID_BYTES
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in node)
                    or type(seq) is not int or not 0 <= seq <= 9223372036854775807):
                raise ValueError("invalid replay identity or sequence")
        if not entries:
            return True
        # One SQLite connection is shared by concurrent receiver workers.
        # Serialize the entire transaction, not only individual statements.
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                for node, seq in entries:
                    row = self.connection.execute(
                        "SELECT seq FROM replay_highwater WHERE node = ?", (node,)
                    ).fetchone()
                    if row is not None and seq <= row[0]:
                        self.connection.execute("ROLLBACK")
                        return False
                    self.connection.execute(
                        "INSERT INTO replay_highwater(node, seq) VALUES (?, ?) "
                        "ON CONFLICT(node) DO UPDATE SET seq=excluded.seq", (node, seq)
                    )
                self.connection.execute("COMMIT")
                return True
            except BaseException:
                if self.connection.in_transaction:
                    self.connection.execute("ROLLBACK")
                raise
    
    def admit_authenticated(self, node, seq, authenticated=False):
        return self.admit_authenticated_batch([(node, seq)], authenticated=authenticated)
