"""Bounded history negative controls; synthetic data, no V2X effectiveness claim."""
import hashlib
import tempfile
import unittest
from research_contracts.independent_checkpoint_issuer import (
    IndependentCheckpointIssuer, CheckpointRefused, MAX_CHECKPOINT_BLOCKS
)

KEY = b"issuer-test-key-at-least-thirty-two-bytes"

class BoundedIssuerInputTests(unittest.TestCase):
    def test_infinite_iterator_is_bounded_and_does_not_commit(self):
        with tempfile.TemporaryDirectory() as d:
            issuer = IndependentCheckpointIssuer(d, "bounded", KEY)
            digest = hashlib.sha256(b"synthetic").hexdigest()
            def infinite():
                while True:
                    yield digest
            with self.assertRaisesRegex(CheckpointRefused, "block limit"):
                issuer.issue(infinite())
            self.assertEqual(issuer._load()["revision"], 0)

    def test_exact_limit_allowed_and_over_limit_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            issuer = IndependentCheckpointIssuer(d, "bounded", KEY)
            digest = hashlib.sha256(b"synthetic").hexdigest()
            receipt = issuer.issue([digest] * MAX_CHECKPOINT_BLOCKS)
            self.assertEqual(receipt["height"], MAX_CHECKPOINT_BLOCKS)
            with self.assertRaisesRegex(CheckpointRefused, "block limit"):
                issuer.issue([digest] * (MAX_CHECKPOINT_BLOCKS + 1))
            self.assertEqual(issuer._load()["revision"], 1)

    def test_non_sequence_rejected_without_state_change(self):
        with tempfile.TemporaryDirectory() as d:
            issuer = IndependentCheckpointIssuer(d, "bounded", KEY)
            for bad in (None, 123, "a" * 64, b"a" * 64):
                with self.subTest(value=type(bad).__name__):
                    with self.assertRaises(CheckpointRefused):
                        issuer.issue(bad)
            self.assertEqual(issuer._load()["revision"], 0)

if __name__ == "__main__":
    unittest.main()
