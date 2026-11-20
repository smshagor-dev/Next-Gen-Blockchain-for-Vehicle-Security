"""Bridge startup must never silently recreate lost replay state."""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from durable_hardware_replay import DurableNonceStore
from hardware_bridge import _hardware_replay_store_path


class BridgeDurableReplayProvisioningTests(unittest.TestCase):
    def test_missing_path_configuration_rejected(self):
        with patch("hardware_bridge.get_env", return_value=""):
            with self.assertRaisesRegex(RuntimeError, "SMARTCAR_HW_REPLAY_DB_PATH"):
                _hardware_replay_store_path()

    def test_deleted_database_rejected_without_recreation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "replay.sqlite")
            with patch("hardware_bridge.get_env", return_value=path):
                with self.assertRaisesRegex(RuntimeError, "missing"):
                    _hardware_replay_store_path()
            self.assertFalse(os.path.exists(path))

    def test_empty_database_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "replay.sqlite")
            open(path, "wb").close()
            with patch("hardware_bridge.get_env", return_value=path):
                with self.assertRaisesRegex(RuntimeError, "empty"):
                    _hardware_replay_store_path()

    def test_explicitly_provisioned_database_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "replay.sqlite")
            store = DurableNonceStore(path, max_entries_per_device=16)
            self.assertIsNone(store.claim("pi-a", "a" * 32, window_seconds=120))
            store.close()
            with patch("hardware_bridge.get_env", return_value=path):
                self.assertEqual(_hardware_replay_store_path(), path)
            reopened = DurableNonceStore(path, max_entries_per_device=16)
            try:
                self.assertEqual(reopened.claim("pi-a", "a" * 32, window_seconds=120), "HW_REPLAY_DETECTED")
            finally:
                reopened.close()

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "real.sqlite")
            store = DurableNonceStore(target, max_entries_per_device=16)
            store.close()
            link = os.path.join(directory, "alias.sqlite")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable")
            with patch("hardware_bridge.get_env", return_value=link):
                with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                    _hardware_replay_store_path()


if __name__ == "__main__":
    unittest.main()
