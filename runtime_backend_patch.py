"""Install runtime-isolated Go backend spawning without changing API behavior.

The patch is intentionally narrow and idempotent. It is installed by main.py
before the dashboard imports the backend. The Go process also self-sanitizes its
environment, so direct Go launches retain a second isolation layer.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from runtime_isolation import (
    build_isolated_child_environment,
    runtime_isolation_metadata,
    subprocess_isolation_kwargs,
)
from smartcar_backend import GoBackend

_INSTALLED = False


def _isolated_spawn_environment(self: GoBackend, root: Path) -> Dict[str, str]:
    environment, audit = build_isolated_child_environment(
        os.environ,
        allowed_smartcar_names={
            "SMARTCAR_GO_API_SECRET",
            "SMARTCAR_GO_DATA_DIR",
            "SMARTCAR_GO_ALLOW_CLASSICAL_ECDH_FALLBACK",
            "SMARTCAR_IDENTITY_ADMISSION_POLICY",
        },
        smartcar_overrides={
            "SMARTCAR_GO_API_SECRET": self.api_secret,
            "SMARTCAR_GO_DATA_DIR": str((root / "logs").resolve()),
        },
        child_kind="go-control-backend",
    )
    self._runtime_isolation_audit = audit
    return environment


def _isolated_ensure_service(self: GoBackend):
    if self._health():
        return

    root = Path(__file__).resolve().parent
    go_root = root / "api" / "go"
    exe = root / "build" / ("smartcar_go_backend.exe" if os.name == "nt" else "smartcar_go_backend")
    if exe.exists():
        cmd = [str(exe)]
        cwd = str(root)
    else:
        cmd = ["go", "run", "."]
        cwd = str(go_root)

    popen_kwargs: Dict[str, Any] = {
        "cwd": cwd,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": self._spawn_environment(root),
    }
    popen_kwargs.update(subprocess_isolation_kwargs())
    self._proc = subprocess.Popen(cmd, **popen_kwargs)

    deadline = time.time() + 12.0
    while time.time() < deadline:
        if self._health():
            return
        if self._proc.poll() is not None:
            raise RuntimeError("Go backend exited before authenticated health verification")
        time.sleep(0.25)
    raise RuntimeError("Authenticated Go backend did not become ready on isolated loopback runtime")


def _runtime_isolation(self: GoBackend) -> Dict[str, object]:
    return runtime_isolation_metadata(getattr(self, "_runtime_isolation_audit", None))


def install_runtime_backend_hardening() -> bool:
    """Install the isolated spawn policy exactly once per Python process."""
    global _INSTALLED
    if _INSTALLED:
        return False
    GoBackend._spawn_environment = _isolated_spawn_environment
    GoBackend._ensure_service = _isolated_ensure_service
    GoBackend.runtime_isolation = _runtime_isolation
    _INSTALLED = True
    return True
