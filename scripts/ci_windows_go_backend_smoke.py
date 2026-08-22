"""Real-process Windows smoke for the authenticated OmniGuard Go backend.

The smoke verifies both the authenticated HTTP control plane and the optional
loopback live socket used by the production desktop dashboard.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import time
from pathlib import Path

from runtime_backend_patch import (
    _terminate_spawned_backend,
    install_runtime_backend_hardening,
)


def _secret() -> str:
    return secrets.token_urlsafe(48)


def _recv_json_line(conn: socket.socket, buffer: bytes = b""):
    while b"\n" not in buffer:
        chunk = conn.recv(65536)
        if not chunk:
            raise RuntimeError("live socket closed before a complete frame")
        buffer += chunk
        if len(buffer) > 16 * 1024 * 1024:
            raise RuntimeError("live socket frame exceeded smoke safety limit")
    line, rest = buffer.split(b"\n", 1)
    value = json.loads(line.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("live socket returned a non-object frame")
    return value, rest


def _verify_live_stream(api_secret: str) -> None:
    deadline = time.time() + 6.0
    last_error = None
    conn = None
    while time.time() < deadline:
        try:
            conn = socket.create_connection(("127.0.0.1", 8788), timeout=1.0)
            break
        except OSError as exc:
            last_error = exc
            time.sleep(0.15)
    if conn is None:
        raise RuntimeError(f"live socket did not become ready: {last_error}")

    try:
        conn.settimeout(3.0)
        challenge, buffer = _recv_json_line(conn)
        if challenge.get("type") != "challenge" or challenge.get("protocol") != "smartcar-live-v1":
            raise RuntimeError("unexpected live socket challenge")
        nonce = str(challenge.get("challenge", ""))
        proof = hmac.new(
            api_secret.encode("utf-8"),
            f"smartcar-live-v1:{nonce}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        conn.sendall(json.dumps({"type": "auth", "proof": proof}, separators=(",", ":")).encode("utf-8") + b"\n")
        ready, buffer = _recv_json_line(conn, buffer)
        if ready.get("type") != "ready":
            raise RuntimeError("live socket authentication was not accepted")

        deadline = time.time() + 4.0
        status = None
        while time.time() < deadline:
            frame, buffer = _recv_json_line(conn, buffer)
            if frame.get("type") == "status" and isinstance(frame.get("data"), dict):
                status = frame["data"]
                break
        if status is None:
            raise RuntimeError("live socket did not stream a status frame")
        if status.get("vehicle_id") != "SMARTCAR_V303_WINDOWS_CI":
            raise RuntimeError("live socket streamed the wrong vehicle identity")
        chain = status.get("chain")
        if not isinstance(chain, list) or not chain:
            raise RuntimeError("live socket streamed an invalid chain snapshot")
        serialized = json.dumps(status).lower()
        for secret_field in ("auth_token", "password", "recovery_key"):
            if secret_field in serialized:
                raise RuntimeError(f"live socket leaked forbidden field: {secret_field}")
    finally:
        conn.close()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    exe = root / "build" / "smartcar_go_backend.exe"
    if os.name != "nt":
        raise RuntimeError("Windows Go backend smoke must run on Windows")
    if not exe.is_file():
        raise RuntimeError(f"fresh Go backend binary is missing: {exe}")

    password = _secret()
    auth_token = _secret()
    api_secret = _secret()
    os.environ["SMARTCAR_GO_API_SECRET"] = api_secret
    os.environ["SMARTCAR_RECOVERY_KEY"] = _secret()
    os.environ["SMARTCAR_GO_API_URL"] = "http://127.0.0.1:8787"
    os.environ["SMARTCAR_GO_RUNTIME_MODE"] = "prebuilt"
    os.environ["SMARTCAR_GO_STARTUP_TIMEOUT_SEC"] = "30"
    os.environ["SMARTCAR_BACKEND_ALLOW_PYTHON_FALLBACK"] = "0"
    os.environ["SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS"] = "0"
    os.environ["SMARTCAR_GO_ENABLE_LIVE_STREAM"] = "1"
    os.environ["SMARTCAR_GO_LIVE_ADDR"] = "127.0.0.1:8788"

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
        _verify_live_stream(api_secret)
        print("Windows authenticated Go backend smoke: PASS (HTTP=authenticated, live_socket=authenticated)")
        return 0
    finally:
        if backend is not None:
            proc = getattr(backend, "_proc", None)
            if proc is not None:
                _terminate_spawned_backend(proc)


if __name__ == "__main__":
    raise SystemExit(main())
