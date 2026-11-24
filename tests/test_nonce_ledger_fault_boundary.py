"""Process-level fault injection across the nonce / ledger boundary.

Engineering counterexample, not proof of physical power-loss durability or
exactly-once ledger delivery. Runs only on local temporary SQLite databases.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hardware_nonce_store import SQLiteNonceStore


class NonceLedgerFaultBoundaryTests(unittest.TestCase):
    def _child(self, code, path, expected):
        proc = subprocess.run(
            [sys.executable, "-c", code, str(path)],
            cwd=str(Path(__file__).resolve().parents[1]),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
        )
        self.assertEqual(proc.returncode, expected,
                         proc.stderr.decode(errors="replace"))

    def test_committed_nonce_survives_crash_before_ledger_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nonce.sqlite"
            self._child("""
import os, sys
from hardware_nonce_store import SQLiteNonceStore
store = SQLiteNonceStore(sys.argv[1], provision=True)
assert store.claim('enrolled-test-node', 'a'*32, ttl_seconds=600)
os._exit(73)
""", path, 73)
            recovered = SQLiteNonceStore(path, provision=False)
            try:
                self.assertFalse(recovered.claim(
                    "enrolled-test-node", "a"*32, ttl_seconds=600))
            finally:
                recovered.close()
            # A valid retry is now rejected despite zero ledger writes.
            # This is an availability counterexample, not an exploit claim.

    def test_uncommitted_nonce_rolled_back_after_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nonce.sqlite"
            store = SQLiteNonceStore(path, provision=True)
            store.close()
            self._child("""
import os, sqlite3, sys
conn = sqlite3.connect(sys.argv[1], isolation_level=None)
conn.execute('PRAGMA journal_mode=WAL')
conn.execute('PRAGMA synchronous=FULL')
conn.execute('BEGIN IMMEDIATE')
conn.execute('INSERT INTO nonce_claims(device,nonce,expires) VALUES(?,?,?)',
             ('enrolled-test-node', 'b'*32, 9999999999.0))
os._exit(74)
""", path, 74)
            recovered = SQLiteNonceStore(path, provision=False)
            try:
                self.assertTrue(recovered.claim(
                    "enrolled-test-node", "b"*32, ttl_seconds=600))
            finally:
                recovered.close()


if __name__ == "__main__":
    unittest.main()
