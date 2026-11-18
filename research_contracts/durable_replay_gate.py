"""Non-actuating durable replay high-water experiment (SQLite, local disk only).

Not a production hardware_bridge receiver. This gate must be invoked ONLY after
message authentication, before admission, and never authorizes actuation.
"""
import sqlite3
from pathlib import Path

MAX_SEQUENCE = (1 << 63) - 1

class DurableReplayGate:
    def __init__(self, path):
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise ValueError("durable replay gate requires a disk path")
        self.db = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        try:
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA busy_timeout=5000")
            self.db.execute("CREATE TABLE IF NOT EXISTS replay (sender TEXT PRIMARY KEY, high_water INTEGER NOT NULL CHECK(high_water >= 0))")
        except BaseException:
            self.db.close()
            raise

    def admit_authenticated(self, sender, sequence, *, authenticated=False):
        """Return accept/replay; fail closed on DB errors.

        Caller must verify HMAC and freshness before calling. Explicit
        authenticated=True prevents accidental admission by unverified callers,
        but is NOT itself proof of cryptographic verification.
        """
        if authenticated is not True:
            return "unauthenticated"
        if not isinstance(sender, str) or not sender or len(sender.encode("utf-8")) > 256 or "\x00" in sender:
            return "invalid"
        if type(sequence) is not int or not 0 <= sequence <= MAX_SEQUENCE:
            return "invalid"
        try:
            self.db.execute("BEGIN IMMEDIATE")
            old = self.db.execute("SELECT high_water FROM replay WHERE sender=?", (sender,)).fetchone()
            if old is not None and sequence <= old[0]:
                self.db.execute("ROLLBACK")
                return "replay"
            self.db.execute("INSERT INTO replay(sender, high_water) VALUES (?, ?) ON CONFLICT(sender) DO UPDATE SET high_water=excluded.high_water", (sender, sequence))
            self.db.execute("COMMIT")
            return "accept"
        except sqlite3.Error:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            return "storage_error"

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
