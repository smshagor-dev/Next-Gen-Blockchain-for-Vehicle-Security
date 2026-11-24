"""Negative controls for durable positive-admission evidence consistency.

These tests modify an offline SQLite snapshot, not a physical controller.
"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from research_contracts.durable_epoch_admission import DurableEpochAdmission
from research_contracts.epoch_admission_controls import Evidence


class DurableQuorumIntegrityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "admission.sqlite"
        self.store = DurableEpochAdmission(self.path)

    def _mutate(self, change):
        with sqlite3.connect(self.path) as db:
            data = json.loads(db.execute(
                "SELECT payload FROM admission_state WHERE id=1").fetchone()[0])
            change(data)
            db.execute("UPDATE admission_state SET payload=? WHERE id=1",
                       (json.dumps(data),))
        with self.assertRaisesRegex(ValueError, "quorum"):
            DurableEpochAdmission(self.path)

    def test_forged_positive_with_one_corrobator_rejected(self):
        def corrupt(data):
            data["buckets"] = [[["incident", 0, "hazard"], ["alice"]]]
            data["admitted"] = [["incident", 0, "hazard"]]
        self._mutate(corrupt)

    def test_quorum_three_rejects_two_corrobators(self):
        self.store = DurableEpochAdmission(self.path, quorum=2)
        def corrupt(data):
            data["bounds"]["quorum"] = 3
            data["buckets"] = [[["incident", 0, "hazard"], ["alice", "bob"]]]
            data["admitted"] = [["incident", 0, "hazard"]]
        with sqlite3.connect(self.path) as db:
            data = json.loads(db.execute("SELECT payload FROM admission_state WHERE id=1").fetchone()[0])
            corrupt(data)
            db.execute("UPDATE admission_state SET payload=? WHERE id=1", (json.dumps(data),))
        with self.assertRaisesRegex(ValueError, "quorum"):
            DurableEpochAdmission(self.path, quorum=3)

    def test_valid_committed_quorum_survives_restart(self):
        first = Evidence("incident", "alice", 0, "n1", "hazard", True)
        second = Evidence("incident", "bob", 0, "n2", "hazard", True)
        self.assertFalse(self.store.admit(first))
        self.assertTrue(self.store.admit(second))
        recovered = DurableEpochAdmission(self.path)
        self.assertFalse(recovered.admit(second))

    def test_nonadmitted_partial_bucket_survives_restart(self):
        first = Evidence("incident", "alice", 0, "n1", "hazard", True)
        second = Evidence("incident", "bob", 0, "n2", "hazard", True)
        self.assertFalse(self.store.admit(first))
        recovered = DurableEpochAdmission(self.path)
        self.assertTrue(recovered.admit(second))


if __name__ == "__main__":
    unittest.main()
