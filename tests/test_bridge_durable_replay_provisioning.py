"""Mainline replay provisioning controls, without serial devices or actuation."""
import os
import tempfile
import unittest
from unittest.mock import patch, Mock

import hardware_bridge as bridge
from hardware_nonce_store import NonceStoreError, SQLiteNonceStore


class BridgeDurableReplayProvisioningTests(unittest.TestCase):
    def open_store(self, path, provision=False):
        with patch.object(bridge, "get_env", return_value=path), patch.object(
            bridge, "get_bool", return_value=provision
        ):
            return bridge._open_hardware_nonce_store("PATH", "PROVISION", "test")

    def test_missing_configuration_rejected(self):
        for path in ("", ":memory:", "file:volatile?mode=memory"):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                self.open_store(path)

    def test_deleted_database_not_recreated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "lost.sqlite")
            with self.assertRaises(NonceStoreError):
                self.open_store(path)
            self.assertFalse(os.path.exists(path))

    def test_empty_database_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "empty.sqlite")
            open(path, "wb").close()
            with self.assertRaises(NonceStoreError):
                self.open_store(path)

    def test_restart_rejects_previous_nonce(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "replay.sqlite")
            first = self.open_store(path, provision=True)
            try:
                self.assertTrue(first.claim("arduino", "a" * 32, ttl_seconds=30))
            finally:
                first.close()
            second = self.open_store(path)
            try:
                self.assertFalse(second.claim("arduino", "a" * 32, ttl_seconds=30))
            finally:
                second.close()

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "real.sqlite")
            SQLiteNonceStore(target, provision=True).close()
            link = os.path.join(directory, "alias.sqlite")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable")
            with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                self.open_store(link)

    def test_serial_missing_store_rejected_before_open(self):
        with patch.object(bridge, "serial") as serial, patch.object(
            bridge, "parse_device_registry", return_value={"test": "x" * 40}
        ), patch.object(bridge, "get_env", side_effect=lambda key, default="": default):
            with self.assertRaisesRegex(RuntimeError, "SERIAL_NONCE_STORE_PATH"):
                bridge.run_arduino_mode(Mock())
            serial.Serial.assert_not_called()


if __name__ == "__main__":
    unittest.main()
