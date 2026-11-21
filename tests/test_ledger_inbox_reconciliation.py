"""Non-actuating crash-boundary and ledger ambiguity negative controls."""
import tempfile
import unittest
from pathlib import Path
from research_contracts.durable_event_inbox import DurableEventInbox
from research_contracts.ledger_inbox_reconciliation import (
    LedgerReconciler, ReconciliationUnavailable, LedgerIdentityConflict, event_id)


class FakeAtomicLedger:
    atomic_append_once = True

    def __init__(self):
        self.records = {}
        self.append_calls = 0
        self.fail_lookup = False
        self.fail_after_write = False

    def lookup(self, identity):
        if self.fail_lookup:
            raise OSError("ledger unavailable")
        return self.records.get(identity)

    def append_once(self, identity, digest):
        self.append_calls += 1
        existing = self.records.get(identity)
        if existing is not None:
            if existing[0] != digest:
                raise LedgerIdentityConflict("conflict")
            return existing[1]
        reference = "simulated:" + identity
        self.records[identity] = (digest, reference)
        if self.fail_after_write:
            raise OSError("ambiguous acknowledgement")
        return reference


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "inbox.sqlite"
        self.inbox = DurableEventInbox(self.path)
        self.ledger = FakeAtomicLedger()
        self.payload = {"speed": 3}

    def tearDown(self):
        self.inbox.close()
        self.temp.cleanup()

    def run_reconcile(self):
        return LedgerReconciler(self.inbox, self.ledger).reconcile(
            "pi1", "nonce1", self.payload)

    def test_append_then_crash_before_mark_recovers_without_duplicate(self):
        def crash():
            raise RuntimeError("injected process interruption")
        with self.assertRaisesRegex(RuntimeError, "interruption"):
            LedgerReconciler(self.inbox, self.ledger).reconcile(
                "pi1", "nonce1", self.payload, after_append=crash)
        self.inbox.close()
        self.inbox = DurableEventInbox(self.path)
        self.assertEqual(self.run_reconcile(), "RECOVERED")
        self.assertEqual(self.ledger.append_calls, 1)
        self.assertEqual(self.inbox.pending(), [])

    def test_ambiguous_append_ack_recovered_without_duplicate(self):
        self.ledger.fail_after_write = True
        with self.assertRaises(ReconciliationUnavailable):
            self.run_reconcile()
        self.ledger.fail_after_write = False
        self.assertEqual(self.run_reconcile(), "RECOVERED")
        self.assertEqual(self.ledger.append_calls, 1)

    def test_lookup_failure_fails_closed(self):
        self.ledger.fail_lookup = True
        with self.assertRaises(ReconciliationUnavailable):
            self.run_reconcile()
        self.assertEqual(self.ledger.append_calls, 0)

    def test_non_atomic_ledger_never_appended(self):
        self.ledger.atomic_append_once = False
        with self.assertRaises(ReconciliationUnavailable):
            self.run_reconcile()
        self.assertEqual(self.ledger.append_calls, 0)

    def test_conflicting_ledger_digest_rejected(self):
        self.ledger.records[event_id("pi1", "nonce1")] = ("wrong", "simulated:wrong")
        with self.assertRaises(LedgerIdentityConflict):
            self.run_reconcile()
        self.assertEqual(self.ledger.append_calls, 0)

    def test_committed_inbox_missing_ledger_fails_closed(self):
        self.assertEqual(self.run_reconcile(), "APPENDED")
        self.ledger.records.clear()
        with self.assertRaises(ReconciliationUnavailable):
            self.run_reconcile()
        self.assertEqual(self.ledger.append_calls, 1)

    def test_normal_retry_does_not_append(self):
        self.assertEqual(self.run_reconcile(), "APPENDED")
        self.assertEqual(self.run_reconcile(), "COMMITTED")
        self.assertEqual(self.ledger.append_calls, 1)


if __name__ == "__main__":
    unittest.main()
