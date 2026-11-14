"""Crash-boundary tests for simulation-only durable nonce admission.

No physical actuator is connected. These tests deliberately kill a child
process to distinguish an uncommitted claim from a committed claim.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hardware_command_receiver_simulator import DurableCommandNonceStore

DEVICE = "bench-node"
NONCE = "a" * 32

CHILD = r"""
import os, sqlite3, sys
from hardware_command_receiver_simulator import DurableCommandNonceStore
path, phase = sys.argv[1:]
store = DurableCommandNonceStore(path)
if phase == 'before_commit':
    db = store._connect()
    db.execute('BEGIN IMMEDIATE')
    db.execute('INSERT INTO accepted_commands(device_id,nonce,accepted_at) VALUES(?,?,?)',
               ('bench-node', 'a'*32, 'now'))
    os._exit(73)
if phase == 'after_commit':
    assert store.claim('bench-node', 'a'*32, 'now')
    os._exit(73)
raise ValueError(phase)
"""


class DurableCommandCrashBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "nonces.sqlite")
        DurableCommandNonceStore(self.path)

    def kill_child(self, phase):
        root = str(Path(__file__).resolve().parents[1])
        env = dict(os.environ)
        env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-c", CHILD, self.path, phase],
            cwd=root, env=env, capture_output=True, text=True, timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 73, result.stderr)

    def test_uncommitted_claim_is_not_consumed_after_process_exit(self):
        self.kill_child("before_commit")
        self.assertTrue(DurableCommandNonceStore(self.path).claim(DEVICE, NONCE, "now"))
        self.assertFalse(DurableCommandNonceStore(self.path).claim(DEVICE, NONCE, "now"))

    def test_committed_claim_remains_consumed_after_process_exit(self):
        self.kill_child("after_commit")
        self.assertFalse(DurableCommandNonceStore(self.path).claim(DEVICE, NONCE, "now"))


if __name__ == "__main__":
    unittest.main()
