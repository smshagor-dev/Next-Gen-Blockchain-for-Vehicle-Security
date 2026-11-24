"""Regression checks for serial restart replay durability (no physical device)."""
import ast
import os
from pathlib import Path
import tempfile
import unittest

from hardware_nonce_store import SQLiteNonceStore

ROOT = Path(__file__).resolve().parents[1]


class ArduinoDurableReplayTests(unittest.TestCase):
    def test_serial_mode_requires_persistent_store_and_closes_it(self):
        source = (ROOT / "hardware_bridge.py").read_text(encoding="utf-8-sig")
        tree = ast.parse(source)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_arduino_mode")
        body = ast.get_source_segment(source, fn)
        self.assertIn("_open_hardware_nonce_store(", body)
        self.assertIn('"SMARTCAR_HW_SERIAL_NONCE_STORE_PATH"', body)
        self.assertIn('"SMARTCAR_HW_SERIAL_NONCE_STORE_PROVISION"', body)
        self.assertLess(body.index("_open_hardware_nonce_store("), body.index("serial.Serial("))
        self.assertIn("durable_nonce_store=nonce_store", body)
        self.assertIn("nonce_store.close()", body)
        self.assertNotIn("durable_nonce_store=None", body)

    def test_nonce_claim_rejected_after_reopen(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "serial-replay.sqlite")
            nonce = "ab" * 16
            first = SQLiteNonceStore(path, provision=True)
            try:
                self.assertTrue(first.claim("arduino-1", nonce, ttl_seconds=15))
            finally:
                first.close()
            recovered = SQLiteNonceStore(path, provision=False)
            try:
                self.assertFalse(recovered.claim("arduino-1", nonce, ttl_seconds=15))
                self.assertTrue(recovered.claim("arduino-1", "cd" * 16, ttl_seconds=15))
            finally:
                recovered.close()

    def test_missing_store_never_auto_provisions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "missing.sqlite")
            with self.assertRaises(Exception):
                SQLiteNonceStore(path, provision=False)
            self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
