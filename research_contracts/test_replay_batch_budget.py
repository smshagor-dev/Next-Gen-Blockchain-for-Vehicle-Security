"""Bounded replay batch admission regressions (simulation only)."""
import os
import sqlite3
import tempfile
import unittest

from sqlite_atomic_replay import SQLiteAtomicReplayGate, MAX_BATCH_ENTRIES


class ReplayBatchBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "replay.sqlite")
        self.gate = SQLiteAtomicReplayGate(self.path)

    def tearDown(self):
        self.gate.close()
        self.temp.cleanup()

    def test_oversize_generator_stops_at_limit_plus_one_without_mutation(self):
        consumed = []
        def unbounded():
            i = 0
            while True:
                consumed.append(i)
                yield ("peer", i)
                i += 1
        with self.assertRaisesRegex(ValueError, "maximum entries"):
            self.gate.admit_authenticated_batch(unbounded(), authenticated=True)
        self.assertEqual(len(consumed), MAX_BATCH_ENTRIES + 1)
        count = self.gate.connection.execute("SELECT COUNT(*) FROM replay_highwater").fetchone()[0]
        self.assertEqual(count, 0)

    def test_exact_limit_commits_and_next_replay_rejected(self):
        entries = (("peer", i) for i in range(MAX_BATCH_ENTRIES))
        self.assertTrue(self.gate.admit_authenticated_batch(entries, authenticated=True))
        self.assertEqual(self.gate.connection.execute(
            "SELECT seq FROM replay_highwater WHERE node='peer'").fetchone()[0], MAX_BATCH_ENTRIES - 1)
        self.assertFalse(self.gate.admit_authenticated("peer", MAX_BATCH_ENTRIES - 1, authenticated=True))

    def test_oversize_does_not_consume_existing_nonce(self):
        self.assertTrue(self.gate.admit_authenticated("peer", 7, authenticated=True))
        with self.assertRaises(ValueError):
            self.gate.admit_authenticated_batch(
                (("peer", i) for i in range(8, MAX_BATCH_ENTRIES + 9)),
                authenticated=True)
        self.assertEqual(self.gate.connection.execute(
            "SELECT seq FROM replay_highwater WHERE node='peer'").fetchone()[0], 7)
        self.assertTrue(self.gate.admit_authenticated("peer", 8, authenticated=True))

    def test_unauthenticated_generator_not_consumed(self):
        def should_not_iterate():
            raise AssertionError("unauthenticated batch was consumed")
            yield ("peer", 1)
        with self.assertRaisesRegex(ValueError, "authentication required"):
            self.gate.admit_authenticated_batch(should_not_iterate(), authenticated=False)


if __name__ == "__main__":
    unittest.main()
