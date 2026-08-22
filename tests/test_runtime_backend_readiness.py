import os
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

# These tests exercise only the launcher/readiness policy. Keep them independent
# from optional dashboard/ML dependencies (NumPy/OpenCV/etc.) by providing the
# minimal GoBackend class contract that runtime_backend_patch captures at import.
# The real backend is exercised separately by Windows Runtime Smoke.
_stub_backend_module = types.ModuleType("smartcar_backend")


class _StubGoBackend:
    def _request(self, *args, **kwargs):
        raise NotImplementedError

    def _refresh(self, *args, **kwargs):
        raise NotImplementedError

    def security_capabilities(self):
        return {}


_stub_backend_module.GoBackend = _StubGoBackend
_original_smartcar_backend = sys.modules.get("smartcar_backend")
sys.modules["smartcar_backend"] = _stub_backend_module
try:
    from runtime_backend_patch import (
        _isolated_ensure_service,
        _loopback_endpoint_is_listening,
        _runtime_mode,
        _select_go_backend_command,
        _startup_timeout_seconds,
    )
finally:
    if _original_smartcar_backend is None:
        sys.modules.pop("smartcar_backend", None)
    else:
        sys.modules["smartcar_backend"] = _original_smartcar_backend


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

    def test_runtime_mode_invalid_value_falls_back_to_auto(self):
        with patch.dict(os.environ, {"SMARTCAR_GO_RUNTIME_MODE": "unexpected"}, clear=True):
            self.assertEqual(_runtime_mode(), "auto")

    def test_auto_mode_prefers_fresh_source_over_local_prebuilt_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            go_root = root / "api" / "go"
            build_root = root / "build"
            go_root.mkdir(parents=True)
            build_root.mkdir(parents=True)
            (go_root / "go.mod").write_text("module example\n", encoding="utf-8")
            (go_root / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
            exe = build_root / ("smartcar_go_backend.exe" if os.name == "nt" else "smartcar_go_backend")
            exe.write_bytes(b"stale-local-binary")

            with patch.dict(os.environ, {}, clear=True), patch(
                "runtime_backend_patch.shutil.which", return_value="C:/Go/bin/go.exe"
            ):
                cmd, cwd, source = _select_go_backend_command(root)

            self.assertEqual(source, "source")
            self.assertEqual(cmd[1:], ["run", "."])
            self.assertEqual(Path(cwd), go_root)

    def test_prebuilt_mode_honors_explicit_operator_choice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            go_root = root / "api" / "go"
            build_root = root / "build"
            go_root.mkdir(parents=True)
            build_root.mkdir(parents=True)
            (go_root / "go.mod").write_text("module example\n", encoding="utf-8")
            (go_root / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
            exe = build_root / ("smartcar_go_backend.exe" if os.name == "nt" else "smartcar_go_backend")
            exe.write_bytes(b"prebuilt")

            with patch.dict(
                os.environ, {"SMARTCAR_GO_RUNTIME_MODE": "prebuilt"}, clear=True
            ), patch("runtime_backend_patch.shutil.which", return_value="C:/Go/bin/go.exe"):
                cmd, cwd, source = _select_go_backend_command(root)

            self.assertEqual(source, "prebuilt")
            self.assertEqual(cmd, [str(exe)])
            self.assertEqual(Path(cwd), root)

    def test_auto_mode_falls_back_to_prebuilt_when_go_toolchain_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            go_root = root / "api" / "go"
            build_root = root / "build"
            go_root.mkdir(parents=True)
            build_root.mkdir(parents=True)
            (go_root / "go.mod").write_text("module example\n", encoding="utf-8")
            (go_root / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
            exe = build_root / ("smartcar_go_backend.exe" if os.name == "nt" else "smartcar_go_backend")
            exe.write_bytes(b"prebuilt")

            with patch.dict(os.environ, {}, clear=True), patch(
                "runtime_backend_patch.shutil.which", return_value=None
            ):
                cmd, cwd, source = _select_go_backend_command(root)

            self.assertEqual(source, "prebuilt")
            self.assertEqual(cmd, [str(exe)])
            self.assertEqual(Path(cwd), root)

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
