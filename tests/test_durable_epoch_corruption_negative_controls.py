"""Fail-closed persisted admission corruption negative controls (synthetic only).

These tests intentionally rewrite SQLite rows as an attacker/fault injector.
They do not demonstrate rollback resistance, physical actuation, or finality.
"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from research_contracts.durable_epoch_admission import DurableEpochAdmission
from research_contracts.epoch_admission_controls import Evidence


class PersistedAdmissionCorruptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "epoch.sqlite"
        self.store = DurableEpochAdmission(self.path)

    def _rewrite(self, change):
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT payload FROM admission_state WHERE id=1").fetchone()
            payload = json.loads(row[0])
            change(payload)
            db.execute("UPDATE admission_state SET payload=? WHERE id=1",
                       (json.dumps(payload, separators=(",", ":")),))

    def _assert_quarantined(self):
        with self.assertRaises(ValueError):
            DurableEpochAdmission(self.path)
        with self.assertRaises(ValueError):
            self.store.admit(Evidence(incident="incident", sender="node-c",
                                      epoch=0, nonce="nonce-c", event="hazard",
                                      verified=True))

    def test_forged_positive_decision_without_quorum_is_rejected(self):
        self._rewrite(lambda p: (p["buckets"].append(
            [["incident", 0, "hazard"], ["node-a"]]),
            p["admitted"].append(["incident", 0, "hazard"])))
        self._assert_quarantined()

    def test_forged_positive_decision_without_bucket_is_rejected(self):
        self._rewrite(lambda p: p["admitted"].append(
            ["incident", 0, "hazard"]))
        self._assert_quarantined()

    def test_duplicate_persisted_nonce_is_rejected(self):
        self._rewrite(lambda p: p["nonces"].extend([
            ["node-a", 0, "nonce-a"], ["node-a", 0, "nonce-a"]]))
        self._assert_quarantined()

    def test_future_epoch_nonce_is_rejected(self):
        self._rewrite(lambda p: p["nonces"].append(
            ["node-a", 1, "nonce-a"]))
        self._assert_quarantined()


if __name__ == "__main__":
    unittest.main()
