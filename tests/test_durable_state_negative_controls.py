"""Corrupt-state negative controls; synthetic non-actuating research validation."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from research_contracts.durable_epoch_admission import DurableEpochAdmission


class DurableStateValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "admission.sqlite"
        DurableEpochAdmission(self.path)

    def mutate(self, change):
        with sqlite3.connect(self.path) as db:
            data = json.loads(db.execute(
                "SELECT payload FROM admission_state WHERE id=1").fetchone()[0])
            change(data)
            db.execute("UPDATE admission_state SET payload=? WHERE id=1",
                       (json.dumps(data),))
        with self.assertRaises(ValueError):
            DurableEpochAdmission(self.path)

    def test_duplicate_admitted_key(self):
        self.mutate(lambda d: d["admitted"].extend(
            [["hazard", 0, "event"], ["hazard", 0, "event"]]))

    def test_nonstring_nonce_key(self):
        self.mutate(lambda d: d["nonces"].append([["nested"], 0, "nonce"]))

    def test_boolean_epoch_nonce(self):
        self.mutate(lambda d: d["nonces"].append(["sender", True, "nonce"]))

    def test_oversized_sender(self):
        self.mutate(lambda d: d["buckets"].append(
            [["incident", 0, "hazard"], ["x" * 129]]))

    def test_invalid_admitted_epoch(self):
        self.mutate(lambda d: d["admitted"].append(["incident", -1, "hazard"]))

    def test_duplicate_nonce(self):
        self.mutate(lambda d: d["nonces"].extend(
            [["sender", 0, "nonce"], ["sender", 0, "nonce"]]))


if __name__ == "__main__":
    unittest.main()
