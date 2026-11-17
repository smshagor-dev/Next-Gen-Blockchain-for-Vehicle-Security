"""Executable SQLite atomicity and restart tests; no hardware access."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlite_atomic_replay import SQLiteAtomicReplayGate


class SQLiteReplayAtomicityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "replay.sqlite")
        self.gate = SQLiteAtomicReplayGate(self.path)

    def tearDown(self):
        self.gate.close()
        self.temp.cleanup()

    def test_later_stale_sequence_rolls_back_first(self):
        self.assertTrue(self.gate.admit_authenticated("b", 9, authenticated=True))
        self.assertFalse(self.gate.admit_authenticated_batch(
            [("a", 1), ("b", 8)], authenticated=True))
        self.assertTrue(self.gate.admit_authenticated("a", 1, authenticated=True))

    def test_duplicate_within_batch_rolls_back(self):
        self.assertFalse(self.gate.admit_authenticated_batch(
            [("a", 1), ("a", 1)], authenticated=True))
        self.assertTrue(self.gate.admit_authenticated("a", 1, authenticated=True))

    def test_restart_persists_highwater(self):
        self.assertTrue(self.gate.admit_authenticated_batch(
            [("a", 3), ("b", 4)], authenticated=True))
        self.gate.close()
        self.gate = SQLiteAtomicReplayGate(self.path)
        self.assertFalse(self.gate.admit_authenticated("a", 3, authenticated=True))
        self.assertTrue(self.gate.admit_authenticated("a", 4, authenticated=True))

    def test_requires_authenticated_input(self):
        with self.assertRaises(ValueError):
            self.gate.admit_authenticated_batch([("a", 1)])
        self.assertTrue(self.gate.admit_authenticated("a", 1, authenticated=True))

    def test_invalid_input_does_not_mutate(self):
        with self.assertRaises(ValueError):
            self.gate.admit_authenticated_batch([("a", 1), ("b", True)], authenticated=True)
        self.assertTrue(self.gate.admit_authenticated("a", 1, authenticated=True))


if __name__ == "__main__":
    unittest.main()
