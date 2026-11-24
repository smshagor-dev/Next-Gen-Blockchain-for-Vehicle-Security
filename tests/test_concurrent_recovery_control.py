"""Concurrency and tamper controls for the non-actuating recovery experiment."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from research_contracts.concurrent_recovery_control import (
    connect, initialize, reconcile, submit, trial,
)


class ConcurrentRecoveryControlTests(unittest.TestCase):
    def test_many_workers_create_one_matching_reservation(self):
        result = trial(24)
        self.assertEqual(result["reservation_count"], 1)
        self.assertTrue(result["digest_matches"])
        self.assertEqual(result["state"], "complete")
        self.assertTrue(all(x in ("reconciled", "already_complete") for x in result["outcomes"]))

    def test_conflicting_anchor_digest_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            local, anchor = Path(folder) / "local.sqlite", Path(folder) / "anchor.sqlite"
            initialize(local, anchor)
            submit(local, "n", b"real")
            with connect(anchor) as db:
                db.execute("INSERT INTO reservations VALUES (?,?)", ("n", "wrong-digest"))
            self.assertEqual(reconcile(local, anchor, "n"), "digest_conflict")
            with connect(local) as db:
                self.assertEqual(db.execute("SELECT state FROM intents WHERE nonce='n'").fetchone()[0], "pending")

    def test_missing_intent_cannot_create_reservation(self):
        with tempfile.TemporaryDirectory() as folder:
            local, anchor = Path(folder) / "local.sqlite", Path(folder) / "anchor.sqlite"
            initialize(local, anchor)
            self.assertEqual(reconcile(local, anchor, "absent"), "missing_intent")
            with connect(anchor) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM reservations").fetchone()[0], 0)

    def test_same_nonce_different_payload_not_reaccepted(self):
        with tempfile.TemporaryDirectory() as folder:
            local, anchor = Path(folder) / "local.sqlite", Path(folder) / "anchor.sqlite"
            initialize(local, anchor)
            submit(local, "n", b"first")
            with self.assertRaises(sqlite3.IntegrityError):
                submit(local, "n", b"second")
            self.assertEqual(reconcile(local, anchor, "n"), "reconciled")


if __name__ == "__main__":
    unittest.main()
