"""Negative controls for durable event admission, not external ledger finality."""
import tempfile
import unittest
from pathlib import Path
from research_contracts.durable_event_inbox import DurableEventInbox, InboxConflict


class InboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "inbox.sqlite"
        self.inbox = DurableEventInbox(self.path)

    def tearDown(self):
        self.inbox.close()
        self.temp.cleanup()

    def test_retry_after_restart_remains_pending(self):
        self.assertEqual(self.inbox.admit("pi1", "nonce1", {"speed": 3}), "NEW")
        self.inbox.close()
        self.inbox = DurableEventInbox(self.path)
        self.assertEqual(self.inbox.admit("pi1", "nonce1", {"speed": 3}), "PENDING")
        self.assertEqual(len(self.inbox.pending()), 1)

    def test_commit_is_idempotent_after_restart(self):
        self.inbox.admit("pi1", "nonce1", {"speed": 3})
        self.inbox.mark_committed("pi1", "nonce1", "ledger:1")
        self.inbox.close()
        self.inbox = DurableEventInbox(self.path)
        self.assertEqual(self.inbox.admit("pi1", "nonce1", {"speed": 3}), "COMMITTED")
        self.assertEqual(self.inbox.pending(), [])
        self.inbox.mark_committed("pi1", "nonce1", "ledger:1")

    def test_conflicting_nonce_payload_rejected(self):
        self.inbox.admit("pi1", "nonce1", {"speed": 3})
        with self.assertRaises(InboxConflict):
            self.inbox.admit("pi1", "nonce1", {"speed": 4})
        self.assertEqual(self.inbox.admit("pi1", "nonce1", {"speed": 3}), "PENDING")

    def test_unverified_commit_and_reference_conflict_rejected(self):
        with self.assertRaises(KeyError):
            self.inbox.mark_committed("pi1", "missing", "ledger:1")
        self.inbox.admit("pi1", "nonce1", {"speed": 3})
        with self.assertRaises(ValueError):
            self.inbox.mark_committed("pi1", "nonce1", "")
        self.inbox.mark_committed("pi1", "nonce1", "ledger:1")
        with self.assertRaises(InboxConflict):
            self.inbox.mark_committed("pi1", "nonce1", "ledger:2")

    def test_distinct_senders_same_nonce_are_independent(self):
        self.assertEqual(self.inbox.admit("pi1", "nonce1", {"x": 1}), "NEW")
        self.assertEqual(self.inbox.admit("pi2", "nonce1", {"x": 1}), "NEW")


if __name__ == "__main__":
    unittest.main()
