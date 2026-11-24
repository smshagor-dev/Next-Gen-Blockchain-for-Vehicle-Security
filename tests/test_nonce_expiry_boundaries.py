"""Adversarial clock/expiry checks against production SQLiteNonceStore."""
import math
import os
import sqlite3
import tempfile
import unittest

from hardware_nonce_store import SQLiteNonceStore, NonceStoreError


class NonceExpiryBoundaryTests(unittest.TestCase):
    def test_overflow_rejected_without_claim(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nonce.sqlite")
            store = SQLiteNonceStore(path, provision=True, clock=lambda: 1.7976931348623157e308)
            try:
                with self.assertRaises(NonceStoreError):
                    store.claim("node-1", "a" * 32, ttl_seconds=600)
                self.assertEqual(store._db.execute("SELECT COUNT(*) FROM nonce_claims").fetchone()[0], 0)
            finally:
                store.close()

    def test_nonadvancing_expiry_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nonce.sqlite")
            store = SQLiteNonceStore(path, provision=True, clock=lambda: 1e30)
            try:
                with self.assertRaises(NonceStoreError):
                    store.claim("node-1", "b" * 32, ttl_seconds=1)
            finally:
                store.close()

    def test_finite_expiry_and_replay_after_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nonce.sqlite")
            store = SQLiteNonceStore(path, provision=True, clock=lambda: 1000.0)
            try:
                self.assertTrue(store.claim("node-1", "c" * 32, ttl_seconds=60))
            finally:
                store.close()
            reopened = SQLiteNonceStore(path, clock=lambda: 1001.0)
            try:
                self.assertFalse(reopened.claim("node-1", "c" * 32, ttl_seconds=60))
                expiry = reopened._db.execute("SELECT expires FROM nonce_claims").fetchone()[0]
                self.assertEqual(expiry, 1060.0)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
