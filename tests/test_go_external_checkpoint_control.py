"""Non-actuating external checkpoint authenticity and rollback controls."""
import hashlib
import hmac
import unittest

from ledger_integrity import LedgerIntegrityError
from research_contracts.go_generation_rollback_control import (
    checkpoint_message, verify_external_checkpoint,
)
from test_go_generation_real_hash_restart import valid_chain

KEY = b"independent-checkpoint-test-only-key-32bytes"


def anchor(chain, height=2, revision=3):
    tip = chain[height - 1]["block_hash"]
    item = {"vehicle_id": "v", "height": height,
            "tip_hash": tip, "revision": revision}
    item["mac"] = hmac.new(
        KEY, checkpoint_message("v", height, tip, revision),
        hashlib.sha256,
    ).hexdigest()
    return item


class ExternalCheckpointControls(unittest.TestCase):
    def setUp(self):
        self.chain = valid_chain(["event-A", "event-B", "event-C"])

    def test_matching_authenticated_prefix_and_append(self):
        self.assertTrue(verify_external_checkpoint(
            self.chain, anchor(self.chain), KEY, "v", minimum_revision=3))

    def test_valid_hash_shorter_history_rejected(self):
        with self.assertRaisesRegex(LedgerIntegrityError, "shorter"):
            verify_external_checkpoint(
                self.chain[:1], anchor(self.chain), KEY, "v")

    def test_valid_hash_rewritten_history_rejected(self):
        rewritten = valid_chain(["event-A", "alternative", "event-C"])
        with self.assertRaisesRegex(LedgerIntegrityError, "tip mismatch"):
            verify_external_checkpoint(rewritten, anchor(self.chain), KEY, "v")

    def test_tampered_signed_height_rejected(self):
        bad = anchor(self.chain)
        bad["height"] = 1
        with self.assertRaisesRegex(LedgerIntegrityError, "authentication"):
            verify_external_checkpoint(self.chain, bad, KEY, "v")

    def test_replayed_old_revision_rejected_with_external_floor(self):
        with self.assertRaisesRegex(LedgerIntegrityError, "revision rollback"):
            verify_external_checkpoint(
                self.chain, anchor(self.chain, revision=2),
                KEY, "v", minimum_revision=3)

    def test_wrong_key_rejected(self):
        with self.assertRaisesRegex(LedgerIntegrityError, "authentication"):
            verify_external_checkpoint(
                self.chain, anchor(self.chain), b"X" * 32, "v")

    def test_unexpected_fields_rejected(self):
        bad = anchor(self.chain)
        bad["untrusted"] = "injected"
        with self.assertRaisesRegex(LedgerIntegrityError, "unexpected"):
            verify_external_checkpoint(self.chain, bad, KEY, "v")


if __name__ == "__main__":
    unittest.main()
