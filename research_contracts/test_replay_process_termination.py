"""Process-termination replay durability checks; not power-loss certification.

Run: python -m unittest discover -s research_contracts -p 'test_replay_process_termination.py' -v
"""
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from sqlite_atomic_replay import SQLiteAtomicReplayGate


class ReplayProcessTerminationTests(unittest.TestCase):
    def _child(self, db, script):
        return subprocess.run(
            [sys.executable, "-c", script, str(ROOT), str(db)],
            capture_output=True, text=True, timeout=15, check=False,
        )

    def test_committed_replay_survives_process_exit_without_close(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "replay.sqlite"
            child = self._child(db, """
import sys
sys.path.insert(0, sys.argv[1])
from sqlite_atomic_replay import SQLiteAtomicReplayGate
g = SQLiteAtomicReplayGate(sys.argv[2])
assert g.admit_authenticated_batch([('vehicle-a', 7), ('vehicle-b', 3)], authenticated=True)
# Abrupt termination after SQLite COMMIT, without close or Python cleanup.
import os
os._exit(0)
""")
            self.assertEqual(child.returncode, 0, child.stderr)
            gate = SQLiteAtomicReplayGate(db)
            try:
                self.assertFalse(gate.admit_authenticated("vehicle-a", 7, authenticated=True))
                self.assertFalse(gate.admit_authenticated("vehicle-b", 3, authenticated=True))
                self.assertTrue(gate.admit_authenticated("vehicle-a", 8, authenticated=True))
            finally:
                gate.close()

    def test_uncommitted_transaction_is_rolled_back_after_process_exit(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "replay.sqlite"
            child = self._child(db, """
import sys
sys.path.insert(0, sys.argv[1])
from sqlite_atomic_replay import SQLiteAtomicReplayGate
g = SQLiteAtomicReplayGate(sys.argv[2])
assert g.admit_authenticated('vehicle-a', 4, authenticated=True)
g.connection.execute('BEGIN IMMEDIATE')
g.connection.execute('UPDATE replay_highwater SET seq=99 WHERE node=?', ('vehicle-a',))
import os
os._exit(0)
""")
            self.assertEqual(child.returncode, 0, child.stderr)
            gate = SQLiteAtomicReplayGate(db)
            try:
                self.assertEqual(gate.connection.execute(
                    "SELECT seq FROM replay_highwater WHERE node='vehicle-a'"
                ).fetchone()[0], 4)
                self.assertFalse(gate.admit_authenticated("vehicle-a", 4, authenticated=True))
                self.assertTrue(gate.admit_authenticated("vehicle-a", 5, authenticated=True))
            finally:
                gate.close()

    def test_corrupted_database_fails_closed_not_fresh_replay_state(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "replay.sqlite"
            db.write_bytes(b"not a sqlite database")
            with self.assertRaises(sqlite3.DatabaseError):
                SQLiteAtomicReplayGate(db)


if __name__ == "__main__":
    unittest.main()
