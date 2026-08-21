"""Shared helpers for the authenticated Python <-> Go loopback control API."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Dict, Optional
from urllib.parse import urlparse


def validate_loopback_base_url(base_url: str) -> str:
    raw = str(base_url or "").strip().rstrip("/")
    parsed = urlparse(raw)
    if parsed.scheme != "http":
        raise ValueError("SMARTCAR_GO_API_URL must use http on loopback")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("SMARTCAR_GO_API_URL must not contain credentials, query, or fragment")
    hostname = (parsed.hostname or "").lower()
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("SMARTCAR_GO_API_URL must target loopback only")
    if parsed.path not in {"", "/"}:
        raise ValueError("SMARTCAR_GO_API_URL must not contain a path prefix")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("SMARTCAR_GO_API_URL has an invalid port")
    return raw


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_api_message(method: str, path: str, timestamp: str, nonce: str, body_hash: str) -> str:
    if not path.startswith("/"):
        raise ValueError("API path must be absolute")
    return "\n".join((method.upper(), path, timestamp, nonce, body_hash.lower()))


def build_signed_headers(
    secret: str,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    if len(secret) < 32:
        raise ValueError("API secret must contain at least 32 characters")
    ts = str(int(time.time()) if timestamp is None else int(timestamp))
    request_nonce = nonce or secrets.token_hex(16)
    try:
        nonce_bytes = bytes.fromhex(request_nonce)
    except ValueError as exc:
        raise ValueError("nonce must be hexadecimal") from exc
    if len(nonce_bytes) < 16:
        raise ValueError("nonce must contain at least 128 bits")
    digest = body_sha256(body)
    canonical = canonical_api_message(method, path, ts, request_nonce, digest)
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-SmartCar-Timestamp": ts,
        "X-SmartCar-Nonce": request_nonce,
        "X-SmartCar-Content-SHA256": digest,
        "X-SmartCar-Signature": signature,
    }


def expected_service_proof(secret: str, challenge: str) -> str:
    return hmac.new(secret.encode("utf-8"), f"health:{challenge}".encode("utf-8"), hashlib.sha256).hexdigest()


def verify_service_proof(secret: str, challenge: str, proof: str) -> bool:
    expected = expected_service_proof(secret, challenge)
    return hmac.compare_digest(str(proof or "").lower(), expected)
