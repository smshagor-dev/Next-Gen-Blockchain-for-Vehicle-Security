"""Real-process Windows smoke for the authenticated OmniGuard Go backend.

This script is intended for the Windows GitHub Actions release gate. It uses a
freshly built prebuilt backend so process ownership/cleanup is deterministic,
while the separate runtime-selection unit tests verify that normal development
`auto` mode prefers checked-out Go source over stale local binaries.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from runtime_backend_patch import (
    _terminate_spawned_backend,
    install_runtime_backend_hardening,
)


def _secret() -> str:
    return secrets.token_urlsafe(48)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    exe = root / "build" / "smartcar_go_backend.exe"
    if os.name != "nt":
        raise RuntimeError("Windows Go backend smoke must run on Windows")
    if not exe.is_file():
        raise RuntimeError(f"fresh Go backend binary is missing: {exe}")

    # Values are generated only in process memory and are never printed.
    password = _secret()
    auth_token = _secret()
    os.environ["SMARTCAR_GO_API_SECRET"] = _secret()
    os.environ["SMARTCAR_RECOVERY_KEY"] = _secret()
    os.environ["SMARTCAR_GO_API_URL"] = "http://127.0.0.1:8787"
    os.environ["SMARTCAR_GO_RUNTIME_MODE"] = "prebuilt"
    os.environ["SMARTCAR_GO_STARTUP_TIMEOUT_SEC"] = "30"
    os.environ["SMARTCAR_BACKEND_ALLOW_PYTHON_FALLBACK"] = "0"
    os.environ["SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS"] = "0"

    install_runtime_backend_hardening()
    from smartcar_backend import GoBackend

    backend = None
    try:
        backend = GoBackend(
            "SMARTCAR_V303_WINDOWS_CI",
            password,
            auth_token,
            "v303-windows-ci-chain.json",
        )
        if getattr(backend, "_backend_runtime_source", "") != "prebuilt":
            raise RuntimeError("Windows smoke did not launch the explicitly selected fresh prebuilt backend")
        if not backend._health():
            raise RuntimeError("Windows smoke lost authenticated Go backend health after initialization")
        verify = backend._request("GET", "/verify")
        if verify.get("valid") is not True:
            raise RuntimeError("Windows smoke backend did not report a valid initialized chain")
        capabilities = backend._request("GET", "/security/capabilities")
        if capabilities.get("local_control_api") != "HMAC-SHA256 + timestamp/nonce replay defense on loopback":
            raise RuntimeError("Windows smoke backend reported an unexpected control API security boundary")
        print("Windows authenticated Go backend smoke: PASS (runtime=prebuilt, health=authenticated)")
        return 0
    finally:
        if backend is not None:
            proc = getattr(backend, "_proc", None)
            if proc is not None:
                _terminate_spawned_backend(proc)


if __name__ == "__main__":
    raise SystemExit(main())
