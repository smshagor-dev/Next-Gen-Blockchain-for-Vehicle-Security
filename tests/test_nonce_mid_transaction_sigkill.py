"""Process-level fault injection at the uncommitted SQLite INSERT boundary.

No real ECU, CAN, or actuator access. This is durability engineering evidence,
not a V2X detection result or a claim of hardware power-loss atomicity.
"""
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hardware_nonce_store import SQLiteNonceStore

DEVICE = "simulated-peer"
NONCE = "a" * 32


class NonceMidTransactionCrashTests(unittest.TestCase):
    def test_sigkill_after_insert_before_commit_rolls_back(self):
        if os.name != "posix" or not hasattr(signal, "SIGKILL"):
            self.skipTest("POSIX SIGKILL required")
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "nonces.sqlite3")
            store = SQLiteNonceStore(db_path, provision=True)
            store.close()
            child = r"""
import os, signal, sys
from hardware_nonce_store import SQLiteNonceStore
class CrashAfterInsert:
    def __init__(self, db):
        self.db = db
    def execute(self, sql, *args):
        result = self.db.execute(sql, *args)
        if sql.lstrip().upper().startswith("INSERT INTO NONCE_CLAIMS"):
            os.kill(os.getpid(), signal.SIGKILL)
        return result
    def __getattr__(self, name):
        return getattr(self.db, name)
store = SQLiteNonceStore(sys.argv[1])
store._db = CrashAfterInsert(store._db)
store.claim("simulated-peer", "a" * 32, ttl_seconds=120)
sys.exit(99)
"""
            result = subprocess.run(
                [sys.executable, "-c", child, db_path],
                cwd=str(Path(__file__).resolve().parents[1]),
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
            conn = sqlite3.connect(db_path)
            try:
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM nonce_claims").fetchone()[0], 0
                )
                self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            finally:
                conn.close()
            reopened = SQLiteNonceStore(db_path)
            try:
                self.assertTrue(reopened.claim(DEVICE, NONCE, ttl_seconds=120))
                self.assertFalse(reopened.claim(DEVICE, NONCE, ttl_seconds=120))
            finally:
                reopened.close()

    def test_committed_nonce_remains_rejected_after_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "nonces.sqlite3")
            first = SQLiteNonceStore(path, provision=True)
            try:
                self.assertTrue(first.claim(DEVICE, NONCE, ttl_seconds=120))
            finally:
                first.close()
            second = SQLiteNonceStore(path)
            try:
                self.assertFalse(second.claim(DEVICE, NONCE, ttl_seconds=120))
            finally:
                second.close()


if __name__ == "__main__":
    unittest.main()
