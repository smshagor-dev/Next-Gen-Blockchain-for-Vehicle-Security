"""SQLite replay clock/commit fault controls; simulation only, no actuation.

Run: python -m unittest discover -s tests -p 'test_nonce_transaction_boundaries.py' -v
"""
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from durable_hardware_replay import DurableNonceStore


class NonceTransactionBoundaries(unittest.TestCase):
    def test_clock_sample_waits_for_write_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "nonce.db")
            store = DurableNonceStore(path, max_entries_per_device=8)
            blocker = sqlite3.connect(path, isolation_level=None)
            blocker.execute("BEGIN IMMEDIATE")
            clock_read = threading.Event()
            finished = threading.Event()
            errors = []
            def sampled_clock():
                clock_read.set()
                return 2000000000.0
            def worker():
                try:
                    with patch("durable_hardware_replay.time.time", side_effect=sampled_clock):
                        result = store.claim("device", "aa" * 16, window_seconds=15)
                        if result is not None:
                            errors.append(result)
                except Exception as exc:
                    errors.append(repr(exc))
                finally:
                    finished.set()
            t = threading.Thread(target=worker, daemon=True)
            try:
                t.start()
                self.assertFalse(clock_read.wait(0.2), "clock sampled before SQLite write lock")
            finally:
                blocker.execute("COMMIT")
                blocker.close()
                t.join(timeout=8)
                store.close()
            self.assertTrue(finished.is_set(), "worker did not finish")
            self.assertTrue(clock_read.is_set(), "clock never sampled")
            self.assertEqual(errors, [])

    def test_uncommitted_nonce_disappears_after_abrupt_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "nonce.db")
            store = DurableNonceStore(path, max_entries_per_device=8)
            store.close()
            script = """
import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1], isolation_level=None)
db.execute('BEGIN IMMEDIATE')
db.execute('INSERT INTO nonce_claims(device,nonce,expires) VALUES(?,?,?)', ('device','bb'*16,9999999999.0))
os._exit(0)
"""
            proc = subprocess.run([sys.executable, "-c", script, path],
                                  cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            recovered = DurableNonceStore(path, max_entries_per_device=8)
            try:
                self.assertIsNone(recovered.claim("device", "bb" * 16, window_seconds=15))
                self.assertEqual(recovered.claim("device", "bb" * 16, window_seconds=15),
                                 "HW_REPLAY_DETECTED")
            finally:
                recovered.close()


if __name__ == "__main__":
    unittest.main()
