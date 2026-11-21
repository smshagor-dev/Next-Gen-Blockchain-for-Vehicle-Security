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


    def test_sqlite_abort_on_second_write_rolls_back_entire_batch(self):
        """An actual SQLite trigger abort must not consume the first nonce."""
        self.gate.connection.execute("""
            CREATE TRIGGER fail_second_node BEFORE INSERT ON replay_highwater
            WHEN NEW.node = 'fault'
            BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END
        """)
        with self.assertRaises(__import__("sqlite3").DatabaseError):
            self.gate.admit_authenticated_batch(
                [("honest", 7), ("fault", 2)], authenticated=True)
        self.assertFalse(self.gate.connection.in_transaction)
        self.assertIsNone(self.gate.connection.execute(
            "SELECT seq FROM replay_highwater WHERE node='honest'").fetchone())
        self.assertTrue(self.gate.admit_authenticated("honest", 7, authenticated=True))

    def test_failed_batch_does_not_advance_existing_highwater(self):
        self.assertTrue(self.gate.admit_authenticated("honest", 4, authenticated=True))
        self.gate.connection.execute("""
            CREATE TRIGGER fail_fault_update BEFORE INSERT ON replay_highwater
            WHEN NEW.node = 'fault'
            BEGIN SELECT RAISE(ABORT, 'injected failure'); END
        """)
        with self.assertRaises(__import__("sqlite3").DatabaseError):
            self.gate.admit_authenticated_batch(
                [("honest", 5), ("fault", 1)], authenticated=True)
        self.assertEqual(self.gate.connection.execute(
            "SELECT seq FROM replay_highwater WHERE node='honest'").fetchone()[0], 4)
        self.assertTrue(self.gate.admit_authenticated("honest", 5, authenticated=True))


if __name__ == "__main__":
    unittest.main()
