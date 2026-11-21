"""Fault-injection integration of authenticated framing with durable replay state.

Simulation-only: never connects to hardware or authorizes actuation.
Run: python -m unittest discover -s research_contracts -p 'test_receiver_durable_integration.py' -v
"""
import os
import sqlite3
import tempfile
import unittest

try:
    from research_contracts.test_receiver_fault_model import BoundedReceiver, FrameError, frame
    from research_contracts.test_durable_replay import DurableReplayGate
except ModuleNotFoundError:
    from test_receiver_fault_model import BoundedReceiver, FrameError, frame
    from test_durable_replay import DurableReplayGate


class ReceiverDurabilityIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "replay.db")
        self.gate = DurableReplayGate(self.path)
        self.key = b"simulated-node-secret"
        self.receiver = BoundedReceiver({"node": self.key}, replay_gate=self.gate)

    def tearDown(self):
        self.gate.close()
        self.tmp.cleanup()

    def test_restart_rejects_replayed_authenticated_frame(self):
        packet = frame("node", 8, {"hazard": True}, self.key)
        self.assertEqual(len(self.receiver.feed(packet)), 1)
        self.gate.close()
        self.gate = DurableReplayGate(self.path)
        self.receiver = BoundedReceiver({"node": self.key}, replay_gate=self.gate)
        with self.assertRaises(FrameError):
            self.receiver.feed(packet)
        self.assertEqual(self.receiver.feed(frame("node", 9, {}, self.key))[0]["seq"], 9)

    def test_invalid_mac_does_not_consume_sequence(self):
        with self.assertRaises(FrameError):
            self.receiver.feed(frame("node", 2, {}, b"wrong"))
        self.assertEqual(self.receiver.feed(frame("node", 2, {}, self.key))[0]["seq"], 2)

    def test_injected_database_failure_never_returns_admission(self):
        self.gate.db.execute(
            'CREATE TRIGGER abort_write BEFORE INSERT ON replay '
            'BEGIN SELECT RAISE(ABORT, "injected failure"); END'
        )
        with self.assertRaises(sqlite3.DatabaseError):
            self.receiver.feed(frame("node", 3, {}, self.key))
        self.assertFalse(self.gate.db.in_transaction)
        self.gate.db.execute("DROP TRIGGER abort_write")
        self.assertEqual(self.receiver.feed(frame("node", 3, {}, self.key))[0]["seq"], 3)

    def test_fragmented_frame_commits_only_after_full_authentication(self):
        packet = frame("node", 4, {}, self.key)
        self.assertEqual(self.receiver.feed(packet[:7]), [])
        self.assertEqual(self.gate.db.execute("SELECT COUNT(*) FROM replay").fetchone()[0], 0)
        self.assertEqual(len(self.receiver.feed(packet[7:])), 1)
        self.assertEqual(self.gate.db.execute("SELECT seq FROM replay WHERE node='node'").fetchone()[0], 4)

    def test_sequence_outside_sqlite_range_rejected_without_write(self):
        with self.assertRaises(FrameError):
            self.receiver.feed(frame("node", 2**63, {}, self.key))
        self.assertEqual(self.gate.db.execute("SELECT COUNT(*) FROM replay").fetchone()[0], 0)

    def test_no_actuation_interface(self):
        self.assertFalse(hasattr(self.receiver, "actuate"))
        self.assertFalse(hasattr(self.gate, "actuate"))


if __name__ == "__main__":
    unittest.main()
