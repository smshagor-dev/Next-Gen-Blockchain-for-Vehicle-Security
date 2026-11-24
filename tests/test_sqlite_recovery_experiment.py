import tempfile
import unittest
from pathlib import Path
from research_contracts.sqlite_recovery_experiment import RecoveryExperiment, RecoveryConflict

class RecoveryExperimentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = Path(self.tmp.name) / "local.sqlite"
        self.b = Path(self.tmp.name) / "anchor.sqlite"
        self.x = RecoveryExperiment(self.a,self.b)

    def tearDown(self):
        self.x.close()
        self.tmp.cleanup()

    def test_restart_repairs_pending_intent(self):
        self.x.stage("event-1", b"message")
        self.x.close()
        self.x = RecoveryExperiment(self.a,self.b)
        self.assertEqual(self.x.reconcile("event-1"), "complete")
        self.assertEqual(self.x.reconcile("event-1"), "complete")

    def test_outage_keeps_pending(self):
        self.x.stage("event-1", b"message")
        self.assertEqual(self.x.reconcile("event-1", anchor_available=False), "pending")
        self.assertEqual(self.x.state("event-1"), "pending")

    def test_conflicting_local_payload_rejected(self):
        self.x.stage("event-1", b"message")
        with self.assertRaises(RecoveryConflict):
            self.x.stage("event-1", b"tampered")

    def test_conflicting_anchor_rejected(self):
        self.x.stage("event-1", b"message")
        self.x.anchor.execute("INSERT INTO reservations VALUES (?,?)", ("event-1", "different"))
        with self.assertRaises(RecoveryConflict):
            self.x.reconcile("event-1")
        self.assertEqual(self.x.state("event-1"), "pending")

    def test_missing_intent_cannot_be_recovered(self):
        with self.assertRaises(RecoveryConflict):
            self.x.reconcile("unknown")

    def test_no_command_dispatch_surface(self):
        self.assertFalse(hasattr(self.x, "authorize"))
        self.assertFalse(hasattr(self.x, "actuate"))

if __name__ == "__main__":
    unittest.main()
