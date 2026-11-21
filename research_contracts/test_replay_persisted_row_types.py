"""Persisted SQLite types must not bypass replay recovery validation."""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlite_atomic_replay import SQLiteAtomicReplayGate, ReplayStoreError


class PersistedReplayRowTests(unittest.TestCase):
    def _provision_and_corrupt(self, node, seq):
        temp = tempfile.TemporaryDirectory()
        path = os.path.join(temp.name, "replay.db")
        gate = SQLiteAtomicReplayGate(path)
        gate.close()
        # SQLite CHECK(seq >= 0) does not reject nonnumeric TEXT: SQLite
        # compares storage classes, rather than parsing arbitrary text.
        with sqlite3.connect(path) as db:
            db.execute("INSERT INTO replay_highwater(node, seq) VALUES (?, ?)", (node, seq))
        return temp, path

    def test_text_highwater_rejected_on_recovery(self):
        temp, path = self._provision_and_corrupt("peer", "not-an-integer")
        try:
            with self.assertRaisesRegex(ReplayStoreError, "invalid persisted"):
                SQLiteAtomicReplayGate(path, require_existing=True)
        finally:
            temp.cleanup()

    def test_oversized_persisted_identity_rejected(self):
        temp, path = self._provision_and_corrupt("é" * 65, 10)
        try:
            with self.assertRaisesRegex(ReplayStoreError, "invalid persisted"):
                SQLiteAtomicReplayGate(path, require_existing=True)
        finally:
            temp.cleanup()

    def test_valid_integer_state_remains_recoverable(self):
        temp, path = self._provision_and_corrupt("peer", 10)
        try:
            gate = SQLiteAtomicReplayGate(path, require_existing=True)
            try:
                self.assertFalse(gate.admit_authenticated("peer", 10, authenticated=True))
                self.assertTrue(gate.admit_authenticated("peer", 11, authenticated=True))
            finally:
                gate.close()
        finally:
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
