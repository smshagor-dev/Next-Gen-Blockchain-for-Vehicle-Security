"""Install isolated Go spawning, policy metadata, and runtime security detection.

The Go process is a local control backend, not a consensus participant. Identity
admission and permissioned quorum are enforced by the Python sync network. The
runtime monitor records normalized failure reason codes only; HTTP bodies,
exception text, credentials, and request payloads are never retained.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from consensus_security import consensus_security_metadata
from identity_security import identity_security_metadata
from ledger_integrity import LedgerIntegrityError
from runtime_isolation import (
    build_isolated_child_environment,
    runtime_isolation_metadata,
    subprocess_isolation_kwargs,
)
from runtime_security_monitor import get_runtime_security_monitor
from smartcar_backend import GoBackend

_INSTALLED = False
_ORIGINAL_REQUEST = GoBackend._request
_ORIGINAL_REFRESH = GoBackend._refresh


def _isolated_spawn_environment(self: GoBackend, root: Path) -> Dict[str, str]:
    environment, audit = build_isolated_child_environment(
        os.environ,
        allowed_smartcar_names={
            "SMARTCAR_GO_API_SECRET",
            "SMARTCAR_GO_DATA_DIR",
            "SMARTCAR_GO_ALLOW_CLASSICAL_ECDH_FALLBACK",
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
            get_runtime_security_monitor().observe(
                "control_api",
                "BACKEND_PROCESS_EXITED_BEFORE_AUTHENTICATED_HEALTH",
                subject=getattr(self, "vehicle_id", ""),
            )
            raise RuntimeError("Go backend exited before authenticated health verification")
        time.sleep(0.25)
    get_runtime_security_monitor().observe(
        "control_api",
        "BACKEND_CONNECTION_UNAVAILABLE",
        subject=getattr(self, "vehicle_id", ""),
    )
    raise RuntimeError("Authenticated Go backend did not become ready on isolated loopback runtime")


def _runtime_reason_from_exception(exc: Exception) -> str:
    text = str(exc).upper()
    if "HTTP 401" in text:
        return "CONTROL_API_HTTP_401"
    if "HTTP 403" in text:
        return "CONTROL_API_HTTP_403"
    if "HTTP 409" in text:
        return "CONTROL_API_HTTP_409"
    if "CONNECTION UNAVAILABLE" in text or "URLERROR" in text or "TIMEOUT" in text:
        return "BACKEND_CONNECTION_UNAVAILABLE"
    return "CONTROL_API_REQUEST_FAILURE"


def _monitored_request(
    self: GoBackend,
    method: str,
    path: str,
    payload: Dict[str, Any] = None,
    recover: bool = True,
) -> Dict[str, Any]:
    try:
        return _ORIGINAL_REQUEST(self, method, path, payload, recover)
    except Exception as exc:
        get_runtime_security_monitor().observe(
            "control_api",
            _runtime_reason_from_exception(exc),
            subject=getattr(self, "vehicle_id", ""),
        )
        raise


def _monitored_refresh(self: GoBackend):
    try:
        return _ORIGINAL_REFRESH(self)
    except LedgerIntegrityError:
        get_runtime_security_monitor().observe(
            "ledger",
            "LEDGER_INTEGRITY_FAILURE",
            subject=getattr(self, "vehicle_id", ""),
        )
        raise


def _runtime_isolation(self: GoBackend) -> Dict[str, object]:
    return runtime_isolation_metadata(getattr(self, "_runtime_isolation_audit", None))


def _runtime_security(self: GoBackend) -> Dict[str, object]:
    return get_runtime_security_monitor().metadata()


def _network_identity_security(self: GoBackend) -> Dict[str, object]:
    return identity_security_metadata()


def _network_consensus_security(self: GoBackend) -> Dict[str, object]:
    return consensus_security_metadata()


def install_runtime_backend_hardening() -> bool:
    """Install isolated spawn, metadata, and monitoring policy exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return False
    GoBackend._spawn_environment = _isolated_spawn_environment
    GoBackend._ensure_service = _isolated_ensure_service
    GoBackend._request = _monitored_request
    GoBackend._refresh = _monitored_refresh
    GoBackend.runtime_isolation = _runtime_isolation
    GoBackend.runtime_security = _runtime_security
    GoBackend.identity_security = _network_identity_security
    GoBackend.consensus_security = _network_consensus_security
    _INSTALLED = True
    return True
