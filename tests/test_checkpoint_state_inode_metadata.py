"""Synthetic negative controls for opened issuer state inode trust boundary."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from research_contracts.independent_checkpoint_issuer import (
    CheckpointRefused, IndependentCheckpointIssuer,
)

KEY = b"simulation-only-key-with-32-plus-bytes"


def digest(s):
    return hashlib.sha256(s.encode()).hexdigest()


@unittest.skipUnless(os.name == "posix", "POSIX inode ownership/permissions")
class CheckpointStateInodeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.issuer = IndependentCheckpointIssuer(self.temp.name, "vehicle-A", KEY)
        self.history = [digest("genesis"), digest("next")]
        self.issuer.issue(self.history)

    def test_world_readable_state_is_refused_without_revision_change(self):
        self.issuer.path.chmod(0o644)
        with self.assertRaisesRegex(CheckpointRefused, "unsafe issuer state metadata"):
            self.issuer.issue(self.history + [digest("third")])
        self.issuer.path.chmod(0o600)
        self.assertEqual(self.issuer.issue(self.history)["revision"], 1)

    def test_hardlinked_state_is_refused(self):
        alias = Path(self.temp.name) / "state-alias"
        os.link(self.issuer.path, alias)
        with self.assertRaisesRegex(CheckpointRefused, "unsafe issuer state metadata"):
            self.issuer.issue(self.history)
        alias.unlink()
        self.assertEqual(self.issuer.issue(self.history)["revision"], 1)

    def test_private_regular_state_allows_restart_and_append(self):
        restarted = IndependentCheckpointIssuer(self.temp.name, "vehicle-A", KEY)
        self.assertEqual(restarted.issue(self.history)["revision"], 1)
        self.assertEqual(restarted.issue(self.history + [digest("third")])["revision"], 2)


if __name__ == "__main__":
    unittest.main()
