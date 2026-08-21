"""Key-provider abstraction and best-effort in-memory secret handling.

This module intentionally does not claim TPM/HSM protection by itself. The
default provider reads policy-validated environment credentials. Hardware-backed
providers can implement the same interface without exporting key material.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Deque, Dict, Mapping, Optional

from credential_policy import validate_secret_separation, validate_secret_value


@dataclass(frozen=True)
class KeyProviderCapabilities:
    provider: str
    hardware_backed: bool
    exportable: bool
    supports_hmac_sha256: bool


@dataclass(frozen=True)
class KeyAccessEvent:
    timestamp: str
    provider: str
    key_name: str
    operation: str
    purpose: str
    success: bool


class KeyAccessAudit:
    """Bounded value-free audit trail for key access operations."""

    def __init__(self, capacity: int = 512):
        self._events: Deque[KeyAccessEvent] = deque(maxlen=max(32, int(capacity)))
        self._lock = threading.Lock()

    def record(self, provider: str, key_name: str, operation: str, purpose: str, success: bool) -> None:
        event = KeyAccessEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            provider=str(provider),
            key_name=str(key_name),
            operation=str(operation),
            purpose=str(purpose or "unspecified"),
            success=bool(success),
        )
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> list[Dict[str, object]]:
        with self._lock:
            return [event.__dict__.copy() for event in self._events]

    def metadata(self) -> Dict[str, object]:
        with self._lock:
            total = len(self._events)
            failures = sum(1 for event in self._events if not event.success)
        return {
            "audit_format": "OMNIGUARD_KEY_ACCESS_AUDIT_V1",
            "event_count": total,
            "failure_count": failures,
            "secret_values_exposed": False,
        }


class SecretBuffer:
    """Mutable secret buffer with best-effort zeroization.

    Python cannot guarantee that no immutable interpreter copies ever exist.
    This class only minimizes the lifetime of the mutable copy it owns.
    """

    def __init__(self, value: str):
        if not isinstance(value, str) or not value:
            raise ValueError("secret buffer requires a non-empty string")
        self._data = bytearray(value.encode("utf-8"))
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def bytes_copy(self) -> bytes:
        """Compatibility escape hatch; callers should avoid retaining the returned immutable copy."""
        if self._closed:
            raise RuntimeError("secret buffer is closed")
        return bytes(self._data)

    def text_copy(self) -> str:
        """Compatibility escape hatch for legacy APIs that require text secrets."""
        if self._closed:
            raise RuntimeError("secret buffer is closed")
        return self._data.decode("utf-8")

    def zeroize(self) -> None:
        if self._closed:
            return
        for index in range(len(self._data)):
            self._data[index] = 0
        self._closed = True

    close = zeroize

    def __enter__(self) -> "SecretBuffer":
        if self._closed:
            raise RuntimeError("secret buffer is closed")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.zeroize()

    def __repr__(self) -> str:
        return f"SecretBuffer(length={len(self._data)}, closed={self._closed}, redacted=True)"


class KeyProvider:
    """Base provider contract.

    Hardware-backed implementations should prefer non-exportable operations such
    as hmac_sha256() and may reject export_secret().
    """

    def __init__(self, audit: Optional[KeyAccessAudit] = None):
        self.audit = audit or KeyAccessAudit()

    @property
    def capabilities(self) -> KeyProviderCapabilities:
        raise NotImplementedError

    def export_secret(self, key_name: str, purpose: str = "runtime") -> SecretBuffer:
        raise NotImplementedError

    def hmac_sha256(self, key_name: str, payload: bytes, purpose: str = "sign") -> str:
        try:
            with self.export_secret(key_name, purpose=purpose) as secret:
                # hmac accepts bytearray, avoiding an additional immutable key copy.
                digest = hmac.new(secret._data, bytes(payload), hashlib.sha256).hexdigest()
            self.audit.record(self.capabilities.provider, key_name, "hmac_sha256", purpose, True)
            return digest
        except Exception:
            self.audit.record(self.capabilities.provider, key_name, "hmac_sha256", purpose, False)
            raise

    def metadata(self) -> Dict[str, object]:
        caps = self.capabilities
        return {
            "provider": caps.provider,
            "hardware_backed": caps.hardware_backed,
            "exportable": caps.exportable,
            "supports_hmac_sha256": caps.supports_hmac_sha256,
            "audit": self.audit.metadata(),
            "secret_values_exposed": False,
        }


class EnvironmentKeyProvider(KeyProvider):
    """Policy-validated software provider backed by process environment values."""

    def __init__(
        self,
        environ: Optional[Mapping[str, str]] = None,
        audit: Optional[KeyAccessAudit] = None,
    ):
        super().__init__(audit=audit)
        self._environ = environ if environ is not None else os.environ

    @property
    def capabilities(self) -> KeyProviderCapabilities:
        return KeyProviderCapabilities(
            provider="environment",
            hardware_backed=False,
            exportable=True,
            supports_hmac_sha256=True,
        )

    def export_secret(self, key_name: str, purpose: str = "runtime") -> SecretBuffer:
        try:
            raw = self._environ.get(key_name)
            value = validate_secret_value(key_name, "" if raw is None else str(raw))
            validate_secret_separation(key_name, value, environ=self._environ)
            result = SecretBuffer(value)
            self.audit.record(self.capabilities.provider, key_name, "export", purpose, True)
            return result
        except Exception:
            self.audit.record(self.capabilities.provider, key_name, "export", purpose, False)
            raise


class UnavailableHardwareKeyProvider(KeyProvider):
    """Fail-closed placeholder for configured TPM2/PKCS#11 providers.

    It prevents a configuration requesting hardware protection from silently
    falling back to exportable environment secrets.
    """

    def __init__(self, provider_name: str, audit: Optional[KeyAccessAudit] = None):
        super().__init__(audit=audit)
        self._provider_name = str(provider_name)

    @property
    def capabilities(self) -> KeyProviderCapabilities:
        return KeyProviderCapabilities(
            provider=self._provider_name,
            hardware_backed=True,
            exportable=False,
            supports_hmac_sha256=False,
        )

    def export_secret(self, key_name: str, purpose: str = "runtime") -> SecretBuffer:
        self.audit.record(self.capabilities.provider, key_name, "export", purpose, False)
        raise RuntimeError(
            f"Hardware key provider {self._provider_name} is configured but no runtime adapter is installed"
        )

    def hmac_sha256(self, key_name: str, payload: bytes, purpose: str = "sign") -> str:
        self.audit.record(self.capabilities.provider, key_name, "hmac_sha256", purpose, False)
        raise RuntimeError(
            f"Hardware key provider {self._provider_name} is configured but no runtime adapter is installed"
        )


def get_key_provider(environ: Optional[Mapping[str, str]] = None) -> KeyProvider:
    env = environ if environ is not None else os.environ
    provider_name = str(env.get("SMARTCAR_KEY_PROVIDER", "environment")).strip().lower()
    require_hardware = str(env.get("SMARTCAR_REQUIRE_HARDWARE_KEY_PROVIDER", "0")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    if provider_name in {"environment", "env", "software"}:
        if require_hardware:
            raise RuntimeError(
                "Hardware-backed key provider is required but SMARTCAR_KEY_PROVIDER resolves to environment"
            )
        return EnvironmentKeyProvider(environ=env)

    if provider_name in {"tpm", "tpm2", "pkcs11", "hsm"}:
        return UnavailableHardwareKeyProvider(provider_name)

    raise RuntimeError(f"Unsupported SMARTCAR_KEY_PROVIDER value: {provider_name}")
