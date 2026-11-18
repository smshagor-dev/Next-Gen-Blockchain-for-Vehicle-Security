"""Non-actuating replay gate fault and restart contracts."""
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from research_contracts.durable_replay_gate import DurableReplayGate, MAX_SEQUENCE

class DurableReplayGateTests(unittest.TestCase):
    def test_restart_persists_highwater(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.sqlite"
            with DurableReplayGate(path) as gate:
                self.assertEqual(gate.admit_authenticated("node-a", 7, authenticated=True), "accept")
                self.assertEqual(gate.admit_authenticated("node-a", 7, authenticated=True), "replay")
            with DurableReplayGate(path) as gate:
                self.assertEqual(gate.admit_authenticated("node-a", 6, authenticated=True), "replay")
                self.assertEqual(gate.admit_authenticated("node-a", 8, authenticated=True), "accept")

    def test_real_subprocess_exit_then_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.sqlite"
            script = ("from research_contracts.durable_replay_gate import DurableReplayGate; "
                      "import sys; g=DurableReplayGate(sys.argv[1]); "
                      "assert g.admit_authenticated('node', 9, authenticated=True)=='accept'; "
                      "g.close()")
            subprocess.run([sys.executable, "-c", script, str(path)], check=True, timeout=10)
            with DurableReplayGate(path) as gate:
                self.assertEqual(gate.admit_authenticated("node", 9, authenticated=True), "replay")

    def test_invalid_and_unauthenticated_never_mutate(self):
        with tempfile.TemporaryDirectory() as tmp:
            with DurableReplayGate(Path(tmp) / "replay.sqlite") as gate:
                for sender, seq, auth in [("a", 1, False), ("a", True, True),
                                           ("a", -1, True), ("a", MAX_SEQUENCE + 1, True),
                                           ("", 1, True), ("a\\x00b", 1, True)]:
                    self.assertNotEqual(gate.admit_authenticated(sender, seq, authenticated=auth), "accept")
                self.assertEqual(gate.admit_authenticated("a", 1, authenticated=True), "accept")

    def test_storage_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = DurableReplayGate(Path(tmp) / "replay.sqlite")
            gate.db.execute("DROP TABLE replay")
            self.assertEqual(gate.admit_authenticated("a", 1, authenticated=True), "storage_error")
            gate.close()

    def test_two_connections_cannot_both_accept_same_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replay.sqlite"
            with DurableReplayGate(path) as a, DurableReplayGate(path) as b:
                self.assertEqual(a.admit_authenticated("a", 1, authenticated=True), "accept")
                self.assertEqual(b.admit_authenticated("a", 1, authenticated=True), "replay")

if __name__ == "__main__":
    unittest.main()
