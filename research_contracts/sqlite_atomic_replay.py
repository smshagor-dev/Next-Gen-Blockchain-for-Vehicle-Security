"""SQLite-backed atomic replay high-water admission for simulation research.

No physical actuator, distributed finality, or blockchain consensus is implied.
Each batch is a single SQLite transaction. One writer is serialized by SQLite.
"""
import sqlite3
import threading
import math
import itertools
import unicodedata
import os

MAX_BATCH_ENTRIES = 4096
MAX_NODE_ID_BYTES = 128


class ReplayStoreError(RuntimeError):
    pass


class SQLiteAtomicReplayGate:
    def __init__(self, path, timeout=5.0, require_existing=False):
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("timeout must be within (0, 60] seconds")
        if type(require_existing) is not bool:
            raise ValueError("require_existing must be bool")
        # A missing replay database must never silently reset sequence history
        # during recovery. Initial provisioning is an explicit separate mode.
        if require_existing:
            if not isinstance(path, (str, bytes, os.PathLike)):
                raise ValueError("persistent replay path required")
            try:
                stat = os.stat(path)
            except FileNotFoundError as exc:
                raise ReplayStoreError("replay database missing; recovery denied") from exc
            if not os.path.isfile(path) or stat.st_size == 0:
                raise ReplayStoreError("replay database is not a provisioned file")
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(
            path, timeout=timeout, isolation_level=None, check_same_thread=False,
            uri=False,
        )
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
        try:
            if require_existing:
                # Never provision schema on recovery: a nonempty unrelated SQLite
                # file would otherwise silently reset all replay principals.
                integrity = self.connection.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise ReplayStoreError("replay database integrity check failed")
                schema = self.connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='replay_highwater'"
                ).fetchone()
                if schema is None:
                    raise ReplayStoreError("replay high-water schema missing; recovery denied")
                columns = self.connection.execute(
                    "PRAGMA table_info(replay_highwater)"
                ).fetchall()
                if [(c[1], c[2].upper(), c[5]) for c in columns] != [
                    ("node", "TEXT", 1), ("seq", "INTEGER", 0)
                ]:
                    raise ReplayStoreError("replay high-water schema mismatch")
                # Validate persisted rows, including constraint-bypassing imports.
                invalid = self.connection.execute(
                    "SELECT 1 FROM replay_highwater "
                    "WHERE typeof(node) != 'text' OR node='' "
                    "OR length(CAST(node AS BLOB)) > 128 "
                    "OR typeof(seq) != 'integer' OR seq < 0 LIMIT 1"
                ).fetchone()
                if invalid is not None:
                    raise ReplayStoreError("invalid persisted replay high-water")
                # SQLite length/type checks cannot detect Unicode aliases or
                # control characters. Apply the same canonical identity policy
                # on recovery as on fresh admission, before accepting traffic.
                for (persisted_node,) in self.connection.execute(
                    "SELECT node FROM replay_highwater"
                ):
                    try:
                        raw_node = persisted_node.encode("utf-8", errors="strict")
                    except UnicodeError as exc:
                        raise ReplayStoreError("invalid persisted replay identity encoding") from exc
                    if (not raw_node
                            or len(raw_node) > MAX_NODE_ID_BYTES
                            or unicodedata.normalize("NFC", persisted_node) != persisted_node
                            or any(ord(ch) < 32 or ord(ch) == 127 for ch in persisted_node)):
                        raise ReplayStoreError("invalid persisted replay identity")
            else:
                self.connection.execute(
                    "CREATE TABLE IF NOT EXISTS replay_highwater "
                    "(node TEXT PRIMARY KEY, seq INTEGER NOT NULL CHECK(seq >= 0))"
                )
        except BaseException:
            self.connection.close()
            raise

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
        for entry in entries:
            if not isinstance(entry, (tuple, list)) or len(entry) != 2:
                raise ValueError("invalid replay entry shape")
            node, seq = entry
            if not isinstance(node, str) or not node:
                raise ValueError("invalid replay identity or sequence")
            try:
                encoded_node = node.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise ValueError("invalid replay identity encoding") from exc
            # Canonicalize at enrollment, not here: silently rewriting signed
            # identities would change the authenticated principal. Reject
            # noncanonical aliases before opening the replay transaction.
            if (len(encoded_node) > MAX_NODE_ID_BYTES
                    or unicodedata.normalize("NFC", node) != node
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
