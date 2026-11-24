"""Fail-closed Arduino replay admission contract; no serial hardware required."""
import os
import tempfile
import unittest
from unittest.mock import patch

from hardware_nonce_store import SQLiteNonceStore, NonceStoreError
import hardware_bridge


class SerialDurableReplayTests(unittest.TestCase):
    def test_missing_serial_nonce_path_fails_before_opening_port(self):
        class PortMustNotOpen:
            def Serial(self, **kwargs):
                raise AssertionError("serial port opened before replay store")
        def env(key, default=""):
            if key == "SMARTCAR_HW_DEVICE_KEYS_JSON":
                return "{}"
            if key == "SMARTCAR_HW_SERIAL_NONCE_STORE_PATH":
                return ""
            return default
        with patch.object(hardware_bridge, "serial", PortMustNotOpen()), \
             patch.object(hardware_bridge, "get_env", side_effect=env), \
             patch.object(hardware_bridge, "parse_device_registry", return_value={}):
            with self.assertRaisesRegex(RuntimeError, "SERIAL_NONCE_STORE_PATH"):
                hardware_bridge.run_arduino_mode(object())

    def test_nonce_replay_rejected_after_close_and_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "serial-nonces.sqlite3")
            first = SQLiteNonceStore(path, provision=True)
            try:
                self.assertTrue(first.claim("arduino-1", "a" * 32, ttl_seconds=30))
            finally:
                first.close()
            recovered = SQLiteNonceStore(path, provision=False)
            try:
                self.assertFalse(recovered.claim("arduino-1", "a" * 32, ttl_seconds=30))
                self.assertTrue(recovered.claim("arduino-1", "b" * 32, ttl_seconds=30))
            finally:
                recovered.close()

    def test_missing_store_cannot_recover_by_creating_empty_database(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "lost.sqlite3")
            with self.assertRaises(NonceStoreError):
                SQLiteNonceStore(path, provision=False)
            self.assertFalse(os.path.exists(path))

    def test_reprovisioning_existing_store_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "serial.sqlite3")
            store = SQLiteNonceStore(path, provision=True)
            store.close()
            with self.assertRaises(NonceStoreError):
                SQLiteNonceStore(path, provision=True)


if __name__ == "__main__":
    unittest.main()
