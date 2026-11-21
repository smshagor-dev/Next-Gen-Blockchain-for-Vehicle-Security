"""Recovery must not silently initialize an unrelated or damaged SQLite file."""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlite_atomic_replay import SQLiteAtomicReplayGate, ReplayStoreError


class RecoverySchemaTests(unittest.TestCase):
    def test_unrelated_sqlite_database_rejected_without_new_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "unrelated.db")
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE unrelated (id INTEGER)")
            with self.assertRaisesRegex(ReplayStoreError, "schema missing"):
                SQLiteAtomicReplayGate(path, require_existing=True)
            with sqlite3.connect(path) as db:
                self.assertIsNone(db.execute(
                    "SELECT name FROM sqlite_master WHERE name='replay_highwater'"
                ).fetchone())

    def test_incompatible_highwater_schema_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wrong.db")
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE replay_highwater (node TEXT, seq TEXT)")
                db.execute("INSERT INTO replay_highwater VALUES ('peer', '9')")
            with self.assertRaisesRegex(ReplayStoreError, "schema mismatch"):
                SQLiteAtomicReplayGate(path, require_existing=True)

    def test_provisioned_highwater_recovers_without_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "valid.db")
            first = SQLiteAtomicReplayGate(path)
            self.assertTrue(first.admit_authenticated("peer", 10, authenticated=True))
            first.close()
            recovered = SQLiteAtomicReplayGate(path, require_existing=True)
            try:
                self.assertFalse(recovered.admit_authenticated("peer", 10, authenticated=True))
                self.assertTrue(recovered.admit_authenticated("peer", 11, authenticated=True))
            finally:
                recovered.close()

    def test_corrupt_nonempty_database_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "corrupt.db")
            Path(path).write_bytes(b"not a sqlite database" * 10)
            with self.assertRaises((ReplayStoreError, sqlite3.DatabaseError)):
                SQLiteAtomicReplayGate(path, require_existing=True)


if __name__ == "__main__":
    unittest.main()
