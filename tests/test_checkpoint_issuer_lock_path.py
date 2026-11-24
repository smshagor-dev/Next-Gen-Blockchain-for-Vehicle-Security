"""Adversarial lock-path controls for the simulation-only checkpoint issuer."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research_contracts.independent_checkpoint_issuer import (
    CheckpointRefused, IndependentCheckpointIssuer,
)

KEY = b"issuer-lock-negative-control-key-32bytes"
HASH = hashlib.sha256(b"genesis").hexdigest()


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX safe open")
class IssuerLockPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.issuer = IndependentCheckpointIssuer(self.tmp.name, "lock-vehicle", KEY)
        self.lock = self.issuer.path.with_suffix(".lock")

    def test_symlink_lock_cannot_modify_target(self):
        target = Path(self.tmp.name) / "outside"
        target.write_bytes(b"sentinel")
        self.lock.symlink_to(target)
        with self.assertRaises(CheckpointRefused):
            self.issuer.issue([HASH])
        self.assertEqual(target.read_bytes(), b"sentinel")
        self.assertFalse(self.issuer.path.exists())

    def test_fifo_lock_refused_without_blocking(self):
        os.mkfifo(self.lock)
        with self.assertRaises(CheckpointRefused):
            self.issuer.issue([HASH])
        self.assertFalse(self.issuer.path.exists())

    def test_world_readable_lock_refused(self):
        self.lock.write_bytes(b"")
        self.lock.chmod(0o644)
        with self.assertRaisesRegex(CheckpointRefused, "metadata"):
            self.issuer.issue([HASH])
        self.assertFalse(self.issuer.path.exists())

    def test_hardlinked_lock_refused(self):
        self.lock.write_bytes(b"")
        os.link(self.lock, Path(self.tmp.name) / "alias.lock")
        with self.assertRaisesRegex(CheckpointRefused, "metadata"):
            self.issuer.issue([HASH])
        self.assertFalse(self.issuer.path.exists())

    def test_inode_replacement_detected_after_lock(self):
        # Deterministically simulate a cooperating writer's lock path being
        # replaced during flock; this is a negative control, not a race proof.
        import fcntl
        original = fcntl.flock

        def replace_after_lock(fd, operation):
            result = original(fd, operation)
            self.lock.unlink()
            self.lock.write_bytes(b"")
            return result

        with patch("research_contracts.independent_checkpoint_issuer.fcntl.flock",
                   side_effect=replace_after_lock):
            with self.assertRaisesRegex(CheckpointRefused, "inode replaced"):
                self.issuer.issue([HASH])
        self.assertFalse(self.issuer.path.exists())

    def test_normal_issue_restart_and_replay_rejection(self):
        receipt = self.issuer.issue([HASH])
        restarted = IndependentCheckpointIssuer(self.tmp.name, "lock-vehicle", KEY)
        self.assertEqual(restarted.issue([HASH]), receipt)
        with self.assertRaises(CheckpointRefused):
            restarted.issue([hashlib.sha256(b"rewrite").hexdigest()])


if __name__ == "__main__":
    unittest.main()
