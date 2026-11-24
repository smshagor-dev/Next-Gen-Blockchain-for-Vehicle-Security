"""Replay identity bounds: no SQLite mutation for oversized/ambiguous identities."""
import os
import tempfile
import unittest

from sqlite_atomic_replay import SQLiteAtomicReplayGate, MAX_NODE_ID_BYTES


class ReplayIdentityBudgetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.gate = SQLiteAtomicReplayGate(os.path.join(self.directory.name, "replay.db"))

    def tearDown(self):
        self.gate.close()
        self.directory.cleanup()

    def test_ascii_boundary_and_utf8_byte_boundary(self):
        self.assertTrue(self.gate.admit_authenticated("a" * MAX_NODE_ID_BYTES, 1, authenticated=True))
        self.assertTrue(self.gate.admit_authenticated("é" * (MAX_NODE_ID_BYTES // 2), 1, authenticated=True))
        with self.assertRaisesRegex(ValueError, "invalid replay identity"):
            self.gate.admit_authenticated("é" * (MAX_NODE_ID_BYTES // 2 + 1), 1, authenticated=True)

    def test_oversized_identity_rejects_whole_batch_before_mutation(self):
        with self.assertRaisesRegex(ValueError, "invalid replay identity"):
            self.gate.admit_authenticated_batch(
                [("valid", 1), ("x" * (MAX_NODE_ID_BYTES + 1), 1)],
                authenticated=True,
            )
        self.assertEqual(self.gate.connection.execute(
            "SELECT COUNT(*) FROM replay_highwater").fetchone()[0], 0)
        self.assertTrue(self.gate.admit_authenticated("valid", 1, authenticated=True))

    def test_control_characters_rejected_without_nonce_consumption(self):
        for node in ("node\\nother", "node\\x00other", "node\\x7fother"):
            with self.subTest(node=repr(node)):
                with self.assertRaisesRegex(ValueError, "invalid replay identity"):
                    self.gate.admit_authenticated(node, 1, authenticated=True)
        self.assertEqual(self.gate.connection.execute(
            "SELECT COUNT(*) FROM replay_highwater").fetchone()[0], 0)

    def test_rejected_batch_preserves_prior_highwater(self):
        self.assertTrue(self.gate.admit_authenticated("valid", 7, authenticated=True))
        with self.assertRaises(ValueError):
            self.gate.admit_authenticated_batch(
                [("valid", 8), ("z" * 129, 1)], authenticated=True)
        self.assertEqual(self.gate.connection.execute(
            "SELECT seq FROM replay_highwater WHERE node='valid'").fetchone()[0], 7)


if __name__ == "__main__":
    unittest.main()
