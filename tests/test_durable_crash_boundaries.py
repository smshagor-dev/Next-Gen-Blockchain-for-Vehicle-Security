"""Subprocess crash-boundary tests: SQLite commit vs positive admission visibility.

Non-actuating research protocol regression. This does not model storage rollback,
power-loss durability, consensus finality, or real ECU safety.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from research_contracts.durable_epoch_admission import DurableEpochAdmission
from research_contracts.epoch_admission_controls import Evidence


def evidence(sender, nonce):
    return Evidence(incident="crash-boundary", sender=sender, epoch=0,
                    nonce=nonce, event="hazard", verified=True)


# Child subprocess executes the actual DurableEpochAdmission transition. The
# SQLite trace hook terminates the process immediately before COMMIT is issued.
# A second mode terminates after the real transaction returned successfully.
CHILD = r"""
import os, sqlite3, sys
from research_contracts.durable_epoch_admission import DurableEpochAdmission
from research_contracts.epoch_admission_controls import Evidence

class CrashAdmission(DurableEpochAdmission):
    def _connect(self):
        db = super()._connect()
        if sys.argv[2] == "before":
            def trace(statement):
                if statement.strip().upper() == "COMMIT":
                    os._exit(73)
            db.set_trace_callback(trace)
        return db

store = CrashAdmission(sys.argv[1])
e = Evidence(incident="crash-boundary", sender="b", epoch=0,
             nonce="n2", event="hazard", verified=True)
result = store.admit(e)
if sys.argv[2] == "after":
    if not result:
        os._exit(75)
    os._exit(74)
os._exit(76)
"""


class CrashBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "admission.sqlite"
        self.store = DurableEpochAdmission(self.db)
        self.assertFalse(self.store.admit(evidence("a", "n1")))

    def child(self, mode):
        env = os.environ.copy()
        return subprocess.run(
            [sys.executable, "-c", CHILD, str(self.db), mode],
            env=env, capture_output=True, text=True, timeout=15,
            check=False,
        )

    def test_crash_before_commit_does_not_publish_quorum(self):
        result = self.child("before")
        self.assertEqual(result.returncode, 73, result.stderr)
        # The uncommitted second sender must not survive subprocess death.
        # Re-submitting the same evidence must still complete the quorum.
        self.assertTrue(DurableEpochAdmission(self.db).admit(evidence("b", "n2")))
        self.assertFalse(DurableEpochAdmission(self.db).admit(evidence("b", "n2")))

    def test_crash_after_commit_retains_one_shot_decision(self):
        result = self.child("after")
        self.assertEqual(result.returncode, 74, result.stderr)
        # The child never returned to its caller after successful commit.
        # Nonetheless the durable decision must not be issued again.
        self.assertFalse(DurableEpochAdmission(self.db).admit(evidence("b", "n2")))
        self.assertFalse(DurableEpochAdmission(self.db).admit(evidence("c", "n3")))

    def test_stop_latch_survives_abrupt_process_exit(self):
        child = r"""
import os, sys
from research_contracts.durable_epoch_admission import DurableEpochAdmission
DurableEpochAdmission(sys.argv[1]).local_emergency_stop()
os._exit(77)
"""
        result = subprocess.run([sys.executable, "-c", child, str(self.db)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertFalse(DurableEpochAdmission(self.db).admit(evidence("b", "n2")))


if __name__ == "__main__":
    unittest.main()
