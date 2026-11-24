import os
import sqlite3
import tempfile
import unittest
from research_contracts.atomic_event_inbox import AtomicEventInbox, AdmissionError

NONCE = "a" * 32

class AtomicInboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "events.db")
        self.inbox = AtomicEventInbox(self.path, provision=True)

    def tearDown(self):
        self.inbox.close()
        self.temp.cleanup()

    def test_replay_preserves_original(self):
        ok, event_id = self.inbox.admit("ecu", NONCE, {"v":1})
        self.assertTrue(ok)
        self.assertEqual(self.inbox.admit("ecu", NONCE, {"v":2}), (False,event_id))
        self.assertEqual(len(self.inbox.pending()), 1)

    def test_transaction_rollback(self):
        self.inbox.db.execute('CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, "injected failure"); END')
        with self.assertRaises(sqlite3.IntegrityError):
            self.inbox.admit("ecu", NONCE, {"v":1})
        self.assertEqual(self.inbox.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

    def test_recovery_after_commit(self):
        self.inbox.admit("ecu", NONCE, {"v":1})
        self.inbox.close()
        self.inbox = AtomicEventInbox(self.path)
        self.assertEqual(len(self.inbox.pending()), 1)
        self.assertFalse(self.inbox.admit("ecu", NONCE, {"v":1})[0])

    def test_delivery_recovery(self):
        _, event_id = self.inbox.admit("ecu", NONCE, {"v":1})
        self.assertEqual(self.inbox.pending()[0][0], event_id)
        self.inbox.mark_delivered(event_id)
        self.assertEqual(self.inbox.pending(), [])

    def test_capacity(self):
        self.inbox.close()
        self.inbox = AtomicEventInbox(self.path, max_events=1)
        self.inbox.admit("ecu", NONCE, {"v":1})
        with self.assertRaises(AdmissionError):
            self.inbox.admit("ecu", "b"*32, {"v":2})

    def test_nonfinite_rejected(self):
        with self.assertRaises(ValueError):
            self.inbox.admit("ecu", NONCE, {"v":float("nan")})

if __name__ == "__main__":
    unittest.main()
