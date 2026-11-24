"""Recovery must reject stored identities that fresh admission rejects."""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlite_atomic_replay import SQLiteAtomicReplayGate, ReplayStoreError


class PersistedIdentityRecoveryTests(unittest.TestCase):
    def check_identity(self, identity, should_recover):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "replay.db")
            gate = SQLiteAtomicReplayGate(path)
            gate.close()
            with sqlite3.connect(path) as db:
                db.execute(
                    "INSERT INTO replay_highwater(node, seq) VALUES (?, ?)",
                    (identity, 7),
                )
            if should_recover:
                recovered = SQLiteAtomicReplayGate(path, require_existing=True)
                try:
                    self.assertFalse(recovered.admit_authenticated(identity, 7, authenticated=True))
                    self.assertTrue(recovered.admit_authenticated(identity, 8, authenticated=True))
                finally:
                    recovered.close()
            else:
                with self.assertRaisesRegex(ReplayStoreError, "invalid persisted"):
                    SQLiteAtomicReplayGate(path, require_existing=True)

    def test_non_nfc_identity_rejected(self):
        self.check_identity("e\u0301", False)

    def test_control_character_rejected(self):
        self.check_identity("peer\nother", False)

    def test_delete_character_rejected(self):
        self.check_identity("peer\x7f", False)

    def test_canonical_unicode_recovered(self):
        self.check_identity("\u00e9", True)


if __name__ == "__main__":
    unittest.main()
