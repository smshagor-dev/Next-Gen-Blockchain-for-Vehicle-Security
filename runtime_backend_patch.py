"""Install isolated Go spawning, policy metadata, runtime detection, and release identity.

The Go process is a local control backend, not a consensus participant. Identity
admission and permissioned quorum are enforced by the Python sync network. The
runtime monitor records normalized failure reason codes only; HTTP bodies,
exception text, credentials, and request payloads are never retained.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

from consensus_security import consensus_security_metadata
from identity_security import identity_security_metadata
from ledger_integrity import LedgerIntegrityError
from release_metadata import release_metadata
from runtime_backend_security import classify_backend_runtime_error
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
_ORIGINAL_SECURITY_CAPABILITIES = GoBackend.security_capabilities


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


def _startup_timeout_seconds() -> float:
    """Return a bounded startup timeout suitable for cold Windows Go builds."""
    raw = os.getenv("SMARTCAR_GO_STARTUP_TIMEOUT_SEC", "45").strip()
    try:
        timeout = float(raw)
    except (TypeError, ValueError):
        timeout = 45.0
    return max(5.0, min(timeout, 120.0))


def _runtime_mode() -> str:
    """Return the requested Go runtime mode, defaulting safely to auto."""
    mode = os.getenv("SMARTCAR_GO_RUNTIME_MODE", "auto").strip().lower()
    if mode not in {"auto", "source", "prebuilt"}:
        return "auto"
    return mode


def _select_go_backend_command(root: Path) -> tuple[list[str], str, str]:
    """Select a fresh source runtime when possible, otherwise a prebuilt binary.

    A repository checkout may contain an untracked build/smartcar_go_backend.exe
    left over from an older source revision. In auto mode, a present Go toolchain
    and source tree therefore take precedence over that local artifact. Packaged
    installs without Go continue to use the prebuilt binary.
    """
    go_root = root / "api" / "go"
    exe = root / "build" / ("smartcar_go_backend.exe" if os.name == "nt" else "smartcar_go_backend")
    go_binary = shutil.which("go")
    source_available = (go_root / "go.mod").is_file() and (go_root / "main.go").is_file()
    mode = _runtime_mode()

    if mode == "source":
        if not source_available:
            raise RuntimeError("SMARTCAR_GO_RUNTIME_MODE=source requested but Go backend source is unavailable")
        if not go_binary:
            raise RuntimeError("SMARTCAR_GO_RUNTIME_MODE=source requested but the Go toolchain was not found")
        return [go_binary, "run", "."], str(go_root), "source"

    if mode == "prebuilt":
        if not exe.exists():
            raise RuntimeError("SMARTCAR_GO_RUNTIME_MODE=prebuilt requested but the Go backend binary is unavailable")
        return [str(exe)], str(root), "prebuilt"

    if source_available and go_binary:
        return [go_binary, "run", "."], str(go_root), "source"
    if exe.exists():
        return [str(exe)], str(root), "prebuilt"

    if source_available:
        raise RuntimeError(
            "Go backend source is available but the Go toolchain was not found and no prebuilt backend exists"
        )
    raise RuntimeError("No Go backend source or compatible prebuilt backend is available")


def _loopback_endpoint_is_listening(base_url: str, timeout: float = 0.20) -> bool:
    """Probe TCP reachability only; authentication is still decided by _health()."""
    try:
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        port = parsed.port
        if host not in {"127.0.0.1", "localhost", "::1"} or port is None:
            return False
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _terminate_spawned_backend(proc: subprocess.Popen) -> None:
    """Best-effort cleanup for only the child process created by this runtime."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3.0)
        return
    except Exception:
        pass
    try:
        proc.kill()
        proc.wait(timeout=3.0)
    except Exception:
        pass


def _isolated_ensure_service(self: GoBackend):
    if self._health():
        return

    # A reachable endpoint that fails authenticated health is deliberately not
    # trusted or killed. This is commonly a stale backend after local credential
    # rotation, but it could be any process. Fail clearly instead of spawning a
    # second backend that cannot own the same loopback port.
    if _loopback_endpoint_is_listening(self.base_url):
        get_runtime_security_monitor().observe(
            "control_api",
            "BACKEND_LOOPBACK_ENDPOINT_AUTHENTICATION_MISMATCH",
            subject=getattr(self, "vehicle_id", ""),
        )
        raise RuntimeError(
            "Configured Go backend loopback endpoint is already in use but failed authenticated health; "
            "stop the stale local backend or choose another loopback endpoint before retrying"
        )

    root = Path(__file__).resolve().parent
    cmd, cwd, runtime_source = _select_go_backend_command(root)
    self._backend_runtime_source = runtime_source

    log_dir = root / "logs" / "processes"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "go-backend.log"
    self._backend_log_path = str(log_path)

    popen_kwargs: Dict[str, Any] = {
        "cwd": cwd,
        "env": self._spawn_environment(root),
    }
    popen_kwargs.update(subprocess_isolation_kwargs())

    # Keep backend diagnostics local and separate from the GUI log. The Go
    # backend never logs credential values; exceptions expose only this path.
    with open(log_path, mode="a", encoding="utf-8", buffering=1) as backend_log:
        backend_log.write(
            f"\n--- backend start {time.strftime('%Y-%m-%d %H:%M:%S')} runtime={runtime_source} ---\n"
        )
        backend_log.flush()
        popen_kwargs["stdout"] = backend_log
        popen_kwargs["stderr"] = subprocess.STDOUT
        self._proc = subprocess.Popen(cmd, **popen_kwargs)

    timeout = _startup_timeout_seconds()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if self._health():
            return
        return_code = self._proc.poll()
        if return_code is not None:
            get_runtime_security_monitor().observe(
                "control_api",
                "BACKEND_PROCESS_EXITED_BEFORE_AUTHENTICATED_HEALTH",
                subject=getattr(self, "vehicle_id", ""),
            )
            raise RuntimeError(
                f"Go backend exited before authenticated health verification "
                f"(exit_code={return_code}, runtime={runtime_source}); see {log_path}"
            )
        time.sleep(0.25)

    _terminate_spawned_backend(self._proc)
    get_runtime_security_monitor().observe(
        "control_api",
        "BACKEND_CONNECTION_UNAVAILABLE",
        subject=getattr(self, "vehicle_id", ""),
    )
    raise RuntimeError(
        f"Authenticated Go backend did not become ready within {timeout:.0f}s "
        f"(runtime={runtime_source}); see {log_path}"
    )


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
            classify_backend_runtime_error(exc),
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


def _release_metadata(self: GoBackend) -> Dict[str, object]:
    return release_metadata()


def _versioned_security_capabilities(self: GoBackend) -> Dict[str, object]:
    """Merge local canonical release identity into authenticated Go metadata."""
    metadata = dict(_ORIGINAL_SECURITY_CAPABILITIES(self))
    release = release_metadata()
    metadata["release_version"] = release["release_version"]
    metadata["release_channel"] = release["release_channel"]
    metadata["internal_hardening_phase"] = release["internal_hardening_phase"]
    return metadata


def install_runtime_backend_hardening() -> bool:
    """Install isolated spawn, metadata, monitoring, and release policy exactly once."""
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
    GoBackend.release_metadata = _release_metadata
    GoBackend.security_capabilities = _versioned_security_capabilities
    _INSTALLED = True
    return True
