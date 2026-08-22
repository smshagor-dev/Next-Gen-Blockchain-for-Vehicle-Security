import os
import socket
import unittest
from unittest.mock import patch

from runtime_backend_patch import (
    _isolated_ensure_service,
    _loopback_endpoint_is_listening,
    _startup_timeout_seconds,
)


class RuntimeBackendReadinessTests(unittest.TestCase):
    def test_startup_timeout_defaults_to_windows_safe_window(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_startup_timeout_seconds(), 45.0)

    def test_startup_timeout_is_bounded(self):
        with patch.dict(os.environ, {"SMARTCAR_GO_STARTUP_TIMEOUT_SEC": "1"}, clear=True):
            self.assertEqual(_startup_timeout_seconds(), 5.0)
        with patch.dict(os.environ, {"SMARTCAR_GO_STARTUP_TIMEOUT_SEC": "900"}, clear=True):
            self.assertEqual(_startup_timeout_seconds(), 120.0)
        with patch.dict(os.environ, {"SMARTCAR_GO_STARTUP_TIMEOUT_SEC": "invalid"}, clear=True):
            self.assertEqual(_startup_timeout_seconds(), 45.0)

    def test_loopback_probe_detects_listening_endpoint(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            self.assertTrue(
                _loopback_endpoint_is_listening(f"http://127.0.0.1:{port}")
            )

    def test_loopback_probe_rejects_non_loopback_target(self):
        self.assertFalse(_loopback_endpoint_is_listening("http://192.0.2.1:8787"))

    def test_occupied_unauthenticated_endpoint_fails_before_spawn(self):
        class DummyBackend:
            vehicle_id = "test-vehicle"

            def __init__(self, base_url):
                self.base_url = base_url

            def _health(self):
                return False

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            backend = DummyBackend(f"http://127.0.0.1:{port}")
            with patch("runtime_backend_patch.subprocess.Popen") as popen:
                with self.assertRaisesRegex(RuntimeError, "already in use"):
                    _isolated_ensure_service(backend)
                popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
