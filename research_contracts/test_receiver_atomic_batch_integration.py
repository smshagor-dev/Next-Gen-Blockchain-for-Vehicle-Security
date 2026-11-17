"""Atomic batch integration regressions; simulation only, no vehicle actuation.

Run: python -m unittest discover -s research_contracts -p 'test_receiver_atomic_batch_integration.py' -v
"""
import os
import sqlite3
import tempfile
import unittest

from test_receiver_fault_model import BoundedReceiver, FrameError, frame
from sqlite_atomic_replay import SQLiteAtomicReplayGate


class AtomicBatchIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "replay.sqlite")
        self.gate = SQLiteAtomicReplayGate(self.path)
        self.key = b"secret-a"

    def tearDown(self):
        self.gate.close()
        self.temp.cleanup()

    def receiver(self):
        return BoundedReceiver({"a": self.key, "b": b"secret-b"}, replay_gate=self.gate)

    def test_later_stale_sequence_rolls_back_earlier_entry(self):
        self.assertTrue(self.gate.admit_authenticated("b", 10, authenticated=True))
        receiver = self.receiver()
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 11, {}, self.key) + frame("b", 9, {}, b"secret-b"))
        self.assertTrue(receiver.poisoned)
        # Sequence 11 was never committed by the rejected batch.
        fresh = self.receiver()
        self.assertEqual([event["seq"] for event in fresh.feed(frame("a", 11, {}, self.key))], [11])

    def test_second_frame_stale_against_disk_state_no_partial_commit(self):
        self.assertTrue(self.gate.admit_authenticated("b", 20, authenticated=True))
        receiver = self.receiver()
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 21, {}, self.key) + frame("b", 20, {}, b"secret-b"))
        self.assertEqual(receiver.accepted_frames, 0)
        self.assertEqual(self.gate.connection.execute(
            "SELECT seq FROM replay_highwater WHERE node='b'").fetchone()[0], 20)

    def test_successful_batch_persists_after_reopen(self):
        receiver = self.receiver()
        self.assertEqual([x["seq"] for x in receiver.feed(
            frame("a", 1, {}, self.key) + frame("a", 2, {}, self.key))], [1, 2])
        self.gate.close()
        self.gate = SQLiteAtomicReplayGate(self.path)
        with self.assertRaises(FrameError):
            self.receiver().feed(frame("a", 2, {}, self.key))
        self.assertEqual(self.receiver().feed(frame("a", 3, {}, self.key))[0]["seq"], 3)

    def test_storage_failure_poison_no_events(self):
        class FailedBatchGate:
            def admit_authenticated_batch(self, entries, authenticated=False):
                raise sqlite3.OperationalError("injected disk failure")
        receiver = BoundedReceiver({"a": self.key}, replay_gate=FailedBatchGate())
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 1, {}, self.key))
        self.assertTrue(receiver.poisoned)
        self.assertEqual(receiver.accepted_frames, 0)


if __name__ == "__main__":
    unittest.main()
