"""SQLite-backed atomic replay high-water admission for simulation research.

No physical actuator, distributed finality, or blockchain consensus is implied.
Each batch is a single SQLite transaction. One writer is serialized by SQLite.
"""
import sqlite3


class ReplayStoreError(RuntimeError):
    pass


class SQLiteAtomicReplayGate:
    def __init__(self, path, timeout=5.0):
        self.connection = sqlite3.connect(path, timeout=timeout, isolation_level=None)
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("CREATE TABLE IF NOT EXISTS replay_highwater (node TEXT PRIMARY KEY, seq INTEGER NOT NULL CHECK(seq >= 0))")

    def close(self):
        self.connection.close()

    def admit_authenticated_batch(self, entries, authenticated=False):
        """Return True iff ALL authenticated (node, seq) entries advance high-water.

        False means no entry was admitted. On SQL failure rollback and propagate.
        The caller must not expose events until this function returns True.
        """
        if authenticated is not True:
            raise ValueError("authentication required")
        entries = list(entries)
        for node, seq in entries:
            if not isinstance(node, str) or not node or type(seq) is not int or not 0 <= seq <= 9223372036854775807:
                raise ValueError("invalid replay identity or sequence")
        if not entries:
            return True
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
