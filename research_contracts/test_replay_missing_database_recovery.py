"""Replay database disappearance regression: recovery must not reset high-water.

These tests cover normal file removal/reopen, not adversarial path swaps,
filesystem power loss, or physically safe actuation.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlite_atomic_replay import SQLiteAtomicReplayGate, ReplayStoreError


class RecoveryProvisioningTests(unittest.TestCase):
    def test_missing_database_denied_without_creating_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "missing.db")
            with self.assertRaises(ReplayStoreError):
                SQLiteAtomicReplayGate(path, require_existing=True)
            self.assertFalse(os.path.exists(path))

    def test_existing_database_retains_highwater_on_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "replay.db")
            gate = SQLiteAtomicReplayGate(path)
            self.assertTrue(gate.admit_authenticated("enrolled", 42, authenticated=True))
            gate.close()
            recovered = SQLiteAtomicReplayGate(path, require_existing=True)
            try:
                self.assertFalse(recovered.admit_authenticated("enrolled", 42, authenticated=True))
                self.assertTrue(recovered.admit_authenticated("enrolled", 43, authenticated=True))
            finally:
                recovered.close()

    def test_removed_database_denied_instead_of_reenrollment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "replay.db")
            gate = SQLiteAtomicReplayGate(path)
            self.assertTrue(gate.admit_authenticated("enrolled", 99, authenticated=True))
            gate.close()
            os.unlink(path)
            with self.assertRaises(ReplayStoreError):
                SQLiteAtomicReplayGate(path, require_existing=True)
            self.assertFalse(os.path.exists(path))

    def test_empty_database_denied_on_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "empty.db")
            Path(path).touch()
            with self.assertRaises(ReplayStoreError):
                SQLiteAtomicReplayGate(path, require_existing=True)

    def test_recovery_flag_requires_explicit_boolean(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "db")
            for invalid in (1, "true", None):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    SQLiteAtomicReplayGate(path, require_existing=invalid)
            self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
