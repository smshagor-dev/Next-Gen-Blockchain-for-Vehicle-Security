"""SQLite-backed replay high-water marks for authenticated simulation events.

The caller MUST authenticate before invoking this gate. Commit precedes admission.
Not a hardware interlock or a rollback-resistant secure-element counter.
"""
import os
import sqlite3
import tempfile
import unittest


class DurableReplayGate:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=2, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=2000")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS replay (node TEXT PRIMARY KEY, seq INTEGER NOT NULL CHECK(seq >= 0))")

    def admit_authenticated(self, node, seq, authenticated=False):
        if authenticated is not True or not isinstance(node, str) or not node or type(seq) is not int or not 0 <= seq <= 9223372036854775807:
            return False
        try:
            self.db.execute("BEGIN IMMEDIATE")
            cur = self.db.execute("INSERT INTO replay(node,seq) VALUES(?,?) ON CONFLICT(node) DO UPDATE SET seq=excluded.seq WHERE excluded.seq > replay.seq", (node, seq))
            accepted = cur.rowcount == 1
            self.db.execute("COMMIT")
            return accepted
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def close(self):
        self.db.close()


class DurableReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "replay.sqlite3")
        self.gate = DurableReplayGate(self.path)

    def tearDown(self):
        self.gate.close()
        self.tmp.cleanup()

    def test_restart_rejects_replay(self):
        self.assertTrue(self.gate.admit_authenticated("node-a", 9, True))
        self.gate.close()
        self.gate = DurableReplayGate(self.path)
        self.assertFalse(self.gate.admit_authenticated("node-a", 9, True))
        self.assertFalse(self.gate.admit_authenticated("node-a", 8, True))
        self.assertTrue(self.gate.admit_authenticated("node-a", 10, True))

    def test_authentication_precondition(self):
        self.assertFalse(self.gate.admit_authenticated("node-a", 1))
        self.assertFalse(self.gate.admit_authenticated("node-a", 1, 1))
        self.assertTrue(self.gate.admit_authenticated("node-a", 1, True))

    def test_per_node_isolation(self):
        self.assertTrue(self.gate.admit_authenticated("a", 4, True))
        self.assertTrue(self.gate.admit_authenticated("b", 1, True))
        self.assertFalse(self.gate.admit_authenticated("a", 3, True))

    def test_invalid_sequence(self):
        for seq in (-1, True, 1.0, 2**63):
            self.assertFalse(self.gate.admit_authenticated("a", seq, True))

    def test_two_connections_serialized(self):
        other = DurableReplayGate(self.path)
        try:
            self.assertTrue(self.gate.admit_authenticated("a", 3, True))
            self.assertFalse(other.admit_authenticated("a", 3, True))
            self.assertTrue(other.admit_authenticated("a", 4, True))
            self.assertFalse(self.gate.admit_authenticated("a", 4, True))
        finally:
            other.close()

    def test_rollback_on_failed_write(self):
        self.gate.db.execute('CREATE TRIGGER fail_write BEFORE INSERT ON replay BEGIN SELECT RAISE(ABORT, "injected failure"); END')
        with self.assertRaises(sqlite3.DatabaseError):
            self.gate.admit_authenticated("a", 1, True)
        self.assertFalse(self.gate.db.in_transaction)
        self.gate.db.execute("DROP TRIGGER fail_write")
        self.assertTrue(self.gate.admit_authenticated("a", 1, True))


if __name__ == "__main__":
    unittest.main()
