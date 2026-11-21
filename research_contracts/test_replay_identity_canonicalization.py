"""Regression coverage for authenticated replay principal canonicalization.

Simulation-only. This is not a physical actuation or identity-enrollment proof.
"""
import os
import sqlite3
import tempfile
import unittest

from research_contracts.sqlite_atomic_replay import SQLiteAtomicReplayGate


class ReplayIdentityCanonicalizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "replay.sqlite")
        self.gate = SQLiteAtomicReplayGate(self.path)

    def tearDown(self):
        self.gate.close()
        self.tmp.cleanup()

    def highwater(self):
        return dict(self.gate.connection.execute(
            "SELECT node, seq FROM replay_highwater ORDER BY node"
        ).fetchall())

    def test_decomposed_unicode_alias_rejected_without_consuming_batch(self):
        self.assertTrue(self.gate.admit_authenticated("node-1", 1, authenticated=True))
        before = self.highwater()
        with self.assertRaises(ValueError):
            self.gate.admit_authenticated_batch(
                [("node-1", 2), ("e\u0301", 1)], authenticated=True
            )
        self.assertEqual(self.highwater(), before)
        self.assertTrue(self.gate.admit_authenticated("node-1", 2, authenticated=True))

    def test_lone_surrogate_fails_closed_as_value_error(self):
        with self.assertRaises(ValueError):
            self.gate.admit_authenticated("bad-\ud800", 1, authenticated=True)
        self.assertEqual(self.highwater(), {})

    def test_malformed_entry_shape_fails_closed(self):
        for malformed in ("node", ("node",), ("node", 1, "extra"), None):
            with self.subTest(malformed=repr(malformed)):
                with self.assertRaises(ValueError):
                    self.gate.admit_authenticated_batch(
                        [("good", 1), malformed], authenticated=True
                    )
                self.assertEqual(self.highwater(), {})

    def test_canonical_unicode_identity_remains_admissible(self):
        self.assertTrue(self.gate.admit_authenticated("\u00e9", 1, authenticated=True))
        self.assertFalse(self.gate.admit_authenticated("\u00e9", 1, authenticated=True))
        self.assertEqual(self.highwater(), {"\u00e9": 1})


if __name__ == "__main__":
    unittest.main()
