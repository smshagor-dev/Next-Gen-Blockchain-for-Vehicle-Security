"""Durability configuration contract tests; not a power-loss experiment."""
import math
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlite_atomic_replay import SQLiteAtomicReplayGate, ReplayStoreError


class ReplayDurabilityConfigurationTests(unittest.TestCase):
    def test_file_store_requires_wal_and_full_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "replay.db")
            gate = SQLiteAtomicReplayGate(path)
            try:
                self.assertEqual(gate.connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
                self.assertEqual(gate.connection.execute("PRAGMA synchronous").fetchone()[0], 2)
                self.assertTrue(gate.admit_authenticated("node", 8, authenticated=True))
            finally:
                gate.close()
            gate = SQLiteAtomicReplayGate(path)
            try:
                self.assertFalse(gate.admit_authenticated("node", 8, authenticated=True))
            finally:
                gate.close()

    def test_memory_store_rejected_instead_of_weakening_journal(self):
        with self.assertRaises(ReplayStoreError):
            SQLiteAtomicReplayGate(":memory:")

    def test_nonfinite_timeout_rejected_before_open(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SQLiteAtomicReplayGate(":memory:", timeout=value)


if __name__ == "__main__":
    unittest.main()
