"""Non-actuating issuer controls; synthetic hashes are not research results."""
import hashlib
import hmac
import os
import tempfile
import unittest
from unittest import mock
from research_contracts.independent_checkpoint_issuer import (
    IndependentCheckpointIssuer, CheckpointRefused, _message,
)

KEY = b"simulation-only-issuer-key-32bytes-long"
def h(value):
    return hashlib.sha256(value.encode()).hexdigest()

class IndependentIssuerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.issuer = IndependentCheckpointIssuer(self.tmp.name, "vehicle-A", KEY)
        self.first = [h("A"), h("B")]

    def test_restart_and_append_revision(self):
        one = self.issuer.issue(self.first)
        restarted = IndependentCheckpointIssuer(self.tmp.name, "vehicle-A", KEY)
        self.assertEqual(restarted.issue(self.first), one)
        two = restarted.issue(self.first + [h("C")])
        self.assertEqual(two["revision"], one["revision"] + 1)
        self.assertTrue(hmac.compare_digest(two["mac"], hmac.new(
            KEY, _message("vehicle-A", 3, h("C"), two["revision"]),
            hashlib.sha256).hexdigest()))

    def test_truncation_refused_after_restart(self):
        self.issuer.issue(self.first)
        with self.assertRaisesRegex(CheckpointRefused, "truncation"):
            IndependentCheckpointIssuer(self.tmp.name, "vehicle-A", KEY).issue(self.first[:1])

    def test_valid_looking_rewrite_refused(self):
        self.issuer.issue(self.first)
        with self.assertRaisesRegex(CheckpointRefused, "rewritten"):
            self.issuer.issue([h("A"), h("different"), h("C")])

    def test_tampered_durable_state_refused(self):
        self.issuer.issue(self.first)
        self.issuer.path.write_text('{"vehicle":"vehicle-A","revision":true,"pins":[]}')
        with self.assertRaisesRegex(CheckpointRefused, "invalid issuer state"):
            self.issuer.issue(self.first)

    def test_invalid_and_empty_inputs(self):
        with self.assertRaisesRegex(CheckpointRefused, "empty"):
            self.issuer.issue([])
        with self.assertRaisesRegex(CheckpointRefused, "invalid tip"):
            self.issuer.issue(["bad"])

    @unittest.skipUnless(os.name == "posix", "POSIX flock only")
    def test_concurrent_writer_refused_without_mutation(self):
        import fcntl
        lock = self.issuer.path.with_suffix(".lock")
        fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(CheckpointRefused, "concurrent issuer"):
                self.issuer.issue(self.first)
            self.assertFalse(self.issuer.path.exists())
        finally:
            os.close(fd)
        self.assertEqual(self.issuer.issue(self.first)["revision"], 1)

    def test_unsupported_locking_fails_closed(self):
        with mock.patch("research_contracts.independent_checkpoint_issuer.fcntl", None):
            with self.assertRaisesRegex(CheckpointRefused, "locking unavailable"):
                self.issuer.issue(self.first)
        self.assertFalse(self.issuer.path.exists())

    def test_vehicle_separation(self):
        self.issuer.issue(self.first)
        other = IndependentCheckpointIssuer(self.tmp.name, "vehicle-B", KEY)
        self.assertEqual(other.issue([h("Z")])["vehicle_id"], "vehicle-B")

if __name__ == "__main__":
    unittest.main()
