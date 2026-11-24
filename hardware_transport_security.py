"""Authenticated, replay-resistant hardware transport primitives for OmniGuard V2X.

This module protects Raspberry Pi <-> bridge message authenticity and integrity.
It does not provide transport confidentiality. Plain TCP is restricted to
loopback by default; an explicit lab-only switch may permit private-address LAN
bench testing. Public/wildcard plaintext endpoints remain rejected.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Mapping, MutableMapping, Optional

from replay_security import BoundedReplayCache


HARDWARE_TRANSPORT_VERSION = "OMNIGUARD_HW_TRANSPORT_V1"
HARDWARE_KDF_VERSION = "OMNIGUARD_HW_KDF_V1"
DEFAULT_REPLAY_WINDOW_SEC = 15
DEFAULT_REPLAY_CACHE_ENTRIES = 2048
DEFAULT_MAX_FRAME_BYTES = 32 * 1024
MAX_EVENT_BYTES = 160

_ENVELOPE_DOMAIN = (HARDWARE_TRANSPORT_VERSION + "\0").encode("utf-8")
_KDF_DOMAIN = (HARDWARE_KDF_VERSION + "\0").encode("utf-8")
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,96}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_KINDS = {"TELEMETRY", "COMMAND"}
_DIRECTIONS = {
    "TELEMETRY": "PI_TO_BRIDGE",
    "COMMAND": "BRIDGE_TO_PI",
}
_REQUIRED_TOP_LEVEL = {
    "version",
    "kind",
    "device_id",
    "timestamp",
    "nonce",
    "payload",
    "mac",
}

_NUMERIC_RANGES = {
    "speed": (0.0, 350.0),
    "acceleration": (-30.0, 30.0),
    "fuel_level": (0.0, 100.0),
    "battery_voltage": (0.0, 100.0),
    "engine_temp": (-60.0, 220.0),
    "gps_lat": (-90.0, 90.0),
    "gps_lon": (-180.0, 180.0),
    "obstacle_distance": (0.0, 5000.0),
    "steering_angle": (-720.0, 720.0),
    "brake_pressure": (0.0, 100.0),
    "throttle_position": (0.0, 100.0),
    "rpm": (0.0, 20000.0),
    "odometer": (0.0, 10_000_000.0),
    "driver_heart_rate_bpm": (20.0, 240.0),
    "driver_drowsiness_score": (0.0, 1.0),
}
_BOOL_FIELDS = {"emergency_brake_active", "driver_unwell"}
_REQUIRED_TELEMETRY_FIELDS = set(_NUMERIC_RANGES) | _BOOL_FIELDS | {"timestamp", "event"}
_ALLOWED_TELEMETRY_FIELDS = _REQUIRED_TELEMETRY_FIELDS | {"source"}
_ALLOWED_COMMAND_FIELDS = {
    "cmd",
    "throttle",
    "brake_pressure",
    "ignition_cut",
    "timestamp",
    "block_index",
    "incident_id",
}


class HardwareTransportError(RuntimeError):
    """Stable fail-closed transport error.

    ``authenticated`` is true only when the envelope MAC was valid before a
    later semantic/replay/identity check failed. Callers can use that distinction
    to avoid letting unauthenticated garbage trigger safety-critical policy.
    """

    def __init__(self, reason: str, *, authenticated: bool = False):
        self.reason = str(reason)
        self.authenticated = bool(authenticated)
        super().__init__(self.reason)


def _raise_constant(value: str):
    raise HardwareTransportError("HW_JSON_NONFINITE_CONSTANT")


def _strict_json_loads(raw: str):
    # JSON permits repeated object members syntactically, but different
    # implementations can choose first/last value. Never authenticate one
    # interpretation and let another consumer act on another interpretation.
    # This hook is applied recursively to envelope AND nested payload objects.
    def unique_members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise HardwareTransportError("HW_JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        return json.loads(raw, parse_constant=_raise_constant,
                          object_pairs_hook=unique_members)
    except HardwareTransportError:
        raise
    except RecursionError as exc:
        # Deeply nested untrusted JSON must fail at the authentication boundary,
        # not escape as an uncaught exception and terminate an ingress worker.
        raise HardwareTransportError("HW_JSON_NESTING_EXCEEDED") from exc
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as exc:
        raise HardwareTransportError("HW_JSON_MALFORMED") from exc


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise HardwareTransportError("HW_CANONICAL_ENCODING_INVALID") from exc


def _parse_utc(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _validate_device_id(device_id: str) -> str:
    value = str(device_id or "").strip()
    if not _DEVICE_ID_RE.fullmatch(value):
        raise HardwareTransportError("HW_DEVICE_ID_INVALID")
    return value


def _validate_secret(secret: str) -> str:
    value = str(secret or "").strip()
    if len(value) < 32:
        raise HardwareTransportError("HW_DEVICE_SECRET_INVALID")
    # Reject unencodable Unicode at enrollment, not later during HMAC KDF.
    # Otherwise a malformed secret can crash a live ingress worker.
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise HardwareTransportError("HW_DEVICE_SECRET_INVALID") from exc
    lowered = value.lower()
    if lowered in {"changeme", "change-me", "default", "password", "secret"}:
        raise HardwareTransportError("HW_DEVICE_SECRET_INVALID")
    return value


def _validate_nonce(nonce: str) -> str:
    value = str(nonce or "").strip().lower()
    if len(value) % 2 or not _HEX_RE.fullmatch(value):
        raise HardwareTransportError("HW_NONCE_INVALID")
    size = len(value) // 2
    if size < 16 or size > 64:
        raise HardwareTransportError("HW_NONCE_INVALID")
    return value


def _validate_kind(kind: str) -> str:
    value = str(kind or "").strip().upper()
    if value not in _KINDS:
        raise HardwareTransportError("HW_MESSAGE_KIND_INVALID")
    return value


def _is_real_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validated_number(name: str, value: object) -> float:
    if not _is_real_number(value):
        raise HardwareTransportError(f"HW_TELEMETRY_TYPE_INVALID_{name.upper()}")
    # Python accepts arbitrarily large JSON integers. Converting one to
    # float can raise OverflowError, which must not escape the transport
    # error boundary or terminate an ingress worker.
    try:
        number = float(value)
    except (OverflowError, ValueError, TypeError) as exc:
        raise HardwareTransportError(f"HW_TELEMETRY_RANGE_INVALID_{name.upper()}") from exc
    if not math.isfinite(number):
        raise HardwareTransportError(f"HW_TELEMETRY_NONFINITE_{name.upper()}")
    minimum, maximum = _NUMERIC_RANGES[name]
    if number < minimum or number > maximum:
        raise HardwareTransportError(f"HW_TELEMETRY_RANGE_INVALID_{name.upper()}")
    return number


def validate_telemetry_payload(
    payload: Mapping[str, object],
    *,
    require_complete: bool = True,
) -> Dict[str, object]:
    """Validate telemetry before it can reach anomaly/ledger state."""
    if not isinstance(payload, Mapping):
        raise HardwareTransportError("HW_TELEMETRY_PAYLOAD_INVALID")
    keys = set(payload)
    if keys - _ALLOWED_TELEMETRY_FIELDS:
        raise HardwareTransportError("HW_TELEMETRY_UNKNOWN_FIELD")
    if require_complete and not _REQUIRED_TELEMETRY_FIELDS.issubset(keys):
        raise HardwareTransportError("HW_TELEMETRY_REQUIRED_FIELD_MISSING")

    result: Dict[str, object] = dict(payload)
    for name in _NUMERIC_RANGES:
        if name in payload:
            result[name] = _validated_number(name, payload[name])
    for name in _BOOL_FIELDS:
        if name in payload and type(payload[name]) is not bool:
            raise HardwareTransportError(f"HW_TELEMETRY_TYPE_INVALID_{name.upper()}")

    if "timestamp" in payload:
        if type(payload["timestamp"]) is not str:
            raise HardwareTransportError("HW_TELEMETRY_TIMESTAMP_INVALID")
        timestamp = payload["timestamp"]
        if _parse_utc(timestamp) is None:
            raise HardwareTransportError("HW_TELEMETRY_TIMESTAMP_INVALID")
        result["timestamp"] = timestamp

    if "event" in payload and type(payload["event"]) is not str:
        raise HardwareTransportError("HW_TELEMETRY_EVENT_INVALID")
    event = payload.get("event", "")
    if "event" in payload:
        if not event or len(event.encode("utf-8")) > MAX_EVENT_BYTES:
            raise HardwareTransportError("HW_TELEMETRY_EVENT_INVALID")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in event):
            raise HardwareTransportError("HW_TELEMETRY_EVENT_INVALID")
        result["event"] = event

    if "source" in payload:
        if type(payload["source"]) is not str:
            raise HardwareTransportError("HW_TELEMETRY_SOURCE_INVALID")
        source = payload["source"]
        if len(source) > 96 or any(ord(ch) < 32 for ch in source):
            raise HardwareTransportError("HW_TELEMETRY_SOURCE_INVALID")
        result["source"] = source
    return result


def build_safe_stop_payload(
    *,
    block_index: int = -1,
    incident_id: str = "",
    timestamp: Optional[datetime] = None,
) -> Dict[str, object]:
    ts = timestamp or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    payload: Dict[str, object] = {
        "cmd": "SAFE_MODE_STOP",
        "throttle": 0,
        "brake_pressure": 100,
        "ignition_cut": 1,
        "timestamp": ts.astimezone(timezone.utc).isoformat(),
        "block_index": int(block_index),
    }
    if incident_id:
        payload["incident_id"] = str(incident_id)[:128]
    return payload


def validate_safe_stop_payload(payload: Mapping[str, object]) -> Dict[str, object]:
    """Accept only the one fail-safe command supported by this research bridge."""
    if not isinstance(payload, Mapping):
        raise HardwareTransportError("HW_COMMAND_PAYLOAD_INVALID")
    if set(payload) - _ALLOWED_COMMAND_FIELDS:
        raise HardwareTransportError("HW_COMMAND_UNKNOWN_FIELD")
    required = {"cmd", "throttle", "brake_pressure", "ignition_cut", "timestamp", "block_index"}
    if not required.issubset(set(payload)):
        raise HardwareTransportError("HW_COMMAND_REQUIRED_FIELD_MISSING")
    if type(payload.get("cmd")) is not str or payload["cmd"] != "SAFE_MODE_STOP":
        raise HardwareTransportError("HW_COMMAND_NOT_ALLOWED")
    if type(payload.get("throttle")) is not int or int(payload["throttle"]) != 0:
        raise HardwareTransportError("HW_COMMAND_SEMANTICS_INVALID")
    if type(payload.get("brake_pressure")) is not int or int(payload["brake_pressure"]) != 100:
        raise HardwareTransportError("HW_COMMAND_SEMANTICS_INVALID")
    if type(payload.get("ignition_cut")) is not int or int(payload["ignition_cut"]) != 1:
        raise HardwareTransportError("HW_COMMAND_SEMANTICS_INVALID")
    if type(payload.get("block_index")) is not int or isinstance(payload.get("block_index"), bool):
        raise HardwareTransportError("HW_COMMAND_SEMANTICS_INVALID")
    timestamp = payload.get("timestamp")
    if type(timestamp) is not str or _parse_utc(timestamp) is None:
        raise HardwareTransportError("HW_COMMAND_TIMESTAMP_INVALID")
    incident_id = payload.get("incident_id", "")
    if type(incident_id) is not str:
        raise HardwareTransportError("HW_COMMAND_INCIDENT_ID_INVALID")
    if len(incident_id) > 128 or any(ord(ch) < 32 for ch in incident_id):
        raise HardwareTransportError("HW_COMMAND_INCIDENT_ID_INVALID")
    return dict(payload)


def derive_directional_key(secret: str, device_id: str, kind: str) -> bytes:
    """Derive independent Pi->bridge and bridge->Pi HMAC keys from one device key."""
    master = _validate_secret(secret).encode("utf-8")
    identity = _validate_device_id(device_id)
    message_kind = _validate_kind(kind)
    material = (
        _KDF_DOMAIN
        + identity.encode("utf-8")
        + b"\0"
        + _DIRECTIONS[message_kind].encode("ascii")
    )
    return hmac.new(master, material, hashlib.sha256).digest()


def _unsigned_envelope(
    device_id: str,
    kind: str,
    payload: Mapping[str, object],
    timestamp: str,
    nonce: str,
) -> Dict[str, object]:
    return {
        "version": HARDWARE_TRANSPORT_VERSION,
        "kind": kind,
        "device_id": device_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "payload": dict(payload),
    }


def build_authenticated_envelope(
    device_id: str,
    secret: str,
    kind: str,
    payload: Mapping[str, object],
    *,
    timestamp: Optional[datetime] = None,
    nonce: Optional[str] = None,
) -> Dict[str, object]:
    identity = _validate_device_id(device_id)
    message_kind = _validate_kind(kind)
    if message_kind == "TELEMETRY":
        clean_payload = validate_telemetry_payload(payload, require_complete=True)
    else:
        clean_payload = validate_safe_stop_payload(payload)

    ts = timestamp or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    timestamp_text = ts.astimezone(timezone.utc).isoformat()
    nonce_text = _validate_nonce(nonce or __import__("secrets").token_hex(16))
    unsigned = _unsigned_envelope(identity, message_kind, clean_payload, timestamp_text, nonce_text)
    key = derive_directional_key(secret, identity, message_kind)
    mac = hmac.new(key, _ENVELOPE_DOMAIN + _canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    envelope = dict(unsigned)
    envelope["mac"] = mac
    return envelope


def encode_authenticated_envelope(envelope: Mapping[str, object], *, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> bytes:
    payload = _canonical_bytes(envelope) + b"\n"
    if len(payload) > max(1024, int(max_frame_bytes)):
        raise HardwareTransportError("HW_FRAME_TOO_LARGE")
    return payload


@dataclass(frozen=True)
class VerifiedHardwareEnvelope:
    device_id: str
    kind: str
    timestamp: str
    nonce: str
    payload: Dict[str, object]


class HardwareEnvelopeVerifier:
    """Verify enrolled-device envelopes with per-device bounded replay caches."""

    def __init__(
        self,
        device_keys: Mapping[str, str],
        *,
        replay_window_sec: int = DEFAULT_REPLAY_WINDOW_SEC,
        replay_cache_entries: int = DEFAULT_REPLAY_CACHE_ENTRIES,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_payload_timestamp_skew_sec: int = 5,
        durable_nonce_store=None,
    ):
        self.replay_window_sec = min(300, max(3, int(replay_window_sec)))
        self.replay_cache_entries = min(65536, max(16, int(replay_cache_entries)))
        self.max_frame_bytes = min(1024 * 1024, max(1024, int(max_frame_bytes)))
        self.max_payload_timestamp_skew_sec = min(300, max(1, int(max_payload_timestamp_skew_sec)))
        self._durable_nonce_store = durable_nonce_store
        self._lock = threading.RLock()
        self._keys: Dict[str, str] = {}
        self._replay: Dict[str, BoundedReplayCache] = {}

        for raw_identity, raw_secret in dict(device_keys or {}).items():
            identity = _validate_device_id(raw_identity)
            secret = _validate_secret(raw_secret)
            for prior in self._keys.values():
                if hmac.compare_digest(secret, prior):
                    raise HardwareTransportError("HW_DEVICE_SECRET_REUSED")
            self._keys[identity] = secret
            self._replay[identity] = BoundedReplayCache(max_entries=self.replay_cache_entries)
        if not self._keys:
            raise HardwareTransportError("HW_DEVICE_REGISTRY_REQUIRED")

    def _parse(self, raw: object) -> Dict[str, object]:
        if isinstance(raw, bytes):
            if len(raw) > self.max_frame_bytes:
                raise HardwareTransportError("HW_FRAME_TOO_LARGE")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HardwareTransportError("HW_FRAME_UTF8_INVALID") from exc
            parsed = _strict_json_loads(text.strip())
        elif isinstance(raw, str):
            try:
                frame_bytes = raw.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise HardwareTransportError("HW_FRAME_UTF8_INVALID") from exc
            if len(frame_bytes) > self.max_frame_bytes:
                raise HardwareTransportError("HW_FRAME_TOO_LARGE")
            parsed = _strict_json_loads(raw.strip())
        elif isinstance(raw, Mapping):
            # Only built-in dictionaries have predictable iteration and item access.
            # User-defined Mapping methods can block, mutate or allocate without
            # respecting any node/byte budget. Never invoke them on ingress.
            if type(raw) is not dict:
                raise HardwareTransportError("HW_ENVELOPE_TYPE_INVALID")
            # In-process callers must obey the same byte budget as TCP callers.
            # Otherwise a giant mapping bypasses the wire framing limit and
            # reaches canonical HMAC encoding with unbounded memory/CPU cost.
            # Bound traversal before canonical JSON allocates a potentially huge
            # intermediate string. This is a fail-closed admission budget, not
            # a guarantee against a hostile in-process Mapping implementation.
            pending = [(raw, 0)]
            visited = set()
            nodes = 0
            string_units = 0
            while pending:
                value, depth = pending.pop()
                nodes += 1
                if nodes > self.max_frame_bytes or depth > 32:
                    raise HardwareTransportError("HW_FRAME_TOO_LARGE")
                if type(value) in (dict, list, tuple):
                    # Check container fan-out BEFORE extending the worklist.
                    # Otherwise one wide in-process container can allocate a
                    # huge pending list even though the later node counter
                    # would eventually reject the envelope.
                    children = len(value) * (2 if type(value) is dict else 1)
                    if children > self.max_frame_bytes - nodes - len(pending):
                        raise HardwareTransportError("HW_FRAME_TOO_LARGE")
                    identity = id(value)
                    if identity in visited:
                        raise HardwareTransportError("HW_FRAME_TOO_LARGE")
                    visited.add(identity)
                    if type(value) is dict:
                        if any(type(k) is not str for k in value):
                            raise HardwareTransportError("HW_CANONICAL_ENCODING_INVALID")
                        pending.extend((v, depth + 1) for v in value.values())
                        pending.extend((k, depth + 1) for k in value.keys())
                    else:
                        pending.extend((v, depth + 1) for v in value)
                elif type(value) is str:
                    string_units += len(value)
                    if string_units > self.max_frame_bytes:
                        raise HardwareTransportError("HW_FRAME_TOO_LARGE")
                elif type(value) is int:
                    # Avoid unbounded decimal conversion of attacker-supplied
                    # in-process big integers before JSON serialization.
                    if value.bit_length() > self.max_frame_bytes * 8:
                        raise HardwareTransportError("HW_FRAME_TOO_LARGE")
                elif type(value) is float:
                    if not math.isfinite(value):
                        raise HardwareTransportError("HW_CANONICAL_ENCODING_INVALID")
                elif value is None or type(value) is bool:
                    pass
                else:
                    # Do not call user-defined __str__, __iter__, __float__,
                    # or JSON encoder hooks while processing ingress.
                    raise HardwareTransportError("HW_CANONICAL_ENCODING_INVALID")
            try:
                encoded = _canonical_bytes(raw)
            except (RecursionError, OverflowError) as exc:
                raise HardwareTransportError("HW_FRAME_TOO_LARGE") from exc
            if len(encoded) > self.max_frame_bytes:
                raise HardwareTransportError("HW_FRAME_TOO_LARGE")
            parsed = _strict_json_loads(encoded.decode("utf-8"))
        else:
            raise HardwareTransportError("HW_ENVELOPE_TYPE_INVALID")
        if not isinstance(parsed, dict):
            raise HardwareTransportError("HW_ENVELOPE_TYPE_INVALID")
        if set(parsed) != _REQUIRED_TOP_LEVEL:
            raise HardwareTransportError("HW_ENVELOPE_FIELDS_INVALID")
        # Never coerce protocol identity, freshness, or authentication fields.
        # bool/int/list values must not alias enrolled string identifiers.
        for field in ("version", "kind", "device_id", "timestamp", "nonce", "mac"):
            if type(parsed[field]) is not str:
                raise HardwareTransportError("HW_ENVELOPE_FIELD_TYPE_INVALID")
        return parsed

    def _prune(self, cache: BoundedReplayCache, now_mono: float) -> None:
        stale = [nonce for nonce, expiry in dict.items(cache) if float(expiry) <= now_mono]
        for nonce in stale:
            dict.pop(cache, nonce, None)

    def _claim_nonce(self, cache: BoundedReplayCache, nonce: str) -> None:
        now_mono = time.monotonic()
        self._prune(cache, now_mono)
        if dict.__contains__(cache, nonce):
            raise HardwareTransportError("HW_REPLAY_DETECTED", authenticated=True)
        if len(cache) >= cache.max_entries:
            cache.saturation_rejections += 1
            raise HardwareTransportError("HW_REPLAY_CACHE_SATURATED", authenticated=True)
        cache[nonce] = now_mono + self.replay_window_sec

    def verify(
        self,
        raw: object,
        *,
        expected_kind: Optional[str] = None,
        expected_device_id: Optional[str] = None,
    ) -> VerifiedHardwareEnvelope:
        parsed = self._parse(raw)
        if str(parsed.get("version", "")) != HARDWARE_TRANSPORT_VERSION:
            raise HardwareTransportError("HW_ENVELOPE_VERSION_INVALID")
        kind = _validate_kind(str(parsed.get("kind", "")))
        if expected_kind is not None and kind != _validate_kind(expected_kind):
            raise HardwareTransportError("HW_MESSAGE_DIRECTION_INVALID")
        identity = _validate_device_id(str(parsed.get("device_id", "")))
        secret = self._keys.get(identity)
        if secret is None:
            raise HardwareTransportError("HW_DEVICE_NOT_ENROLLED")

        timestamp_text = str(parsed.get("timestamp", ""))
        timestamp = _parse_utc(timestamp_text)
        if timestamp is None:
            raise HardwareTransportError("HW_ENVELOPE_TIMESTAMP_INVALID")
        if abs((datetime.now(timezone.utc) - timestamp).total_seconds()) > self.replay_window_sec:
            raise HardwareTransportError("HW_ENVELOPE_STALE")
        nonce = _validate_nonce(str(parsed.get("nonce", "")))
        received_mac = str(parsed.get("mac", "")).lower()
        if len(received_mac) != 64 or not _HEX_RE.fullmatch(received_mac):
            raise HardwareTransportError("HW_ENVELOPE_MAC_INVALID")

        unsigned = dict(parsed)
        unsigned.pop("mac", None)
        key = derive_directional_key(secret, identity, kind)
        expected_mac = hmac.new(
            key,
            _ENVELOPE_DOMAIN + _canonical_bytes(unsigned),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(received_mac, expected_mac):
            raise HardwareTransportError("HW_ENVELOPE_MAC_INVALID")

        # MAC is valid from this point onward. Identity binding, payload checks,
        # and replay state can now distinguish authenticated faults from garbage.
        if expected_device_id is not None and identity != _validate_device_id(expected_device_id):
            raise HardwareTransportError("HW_DEVICE_IDENTITY_MISMATCH", authenticated=True)

        payload = parsed.get("payload")
        try:
            if kind == "TELEMETRY":
                clean_payload = validate_telemetry_payload(payload, require_complete=True)  # type: ignore[arg-type]
            else:
                clean_payload = validate_safe_stop_payload(payload)  # type: ignore[arg-type]
        except HardwareTransportError as exc:
            raise HardwareTransportError(exc.reason, authenticated=True) from exc

        payload_timestamp = _parse_utc(str(clean_payload.get("timestamp", "")))
        if payload_timestamp is None or abs((payload_timestamp - timestamp).total_seconds()) > self.max_payload_timestamp_skew_sec:
            raise HardwareTransportError("HW_PAYLOAD_TIMESTAMP_MISMATCH", authenticated=True)

        with self._lock:
            if self._durable_nonce_store is not None:
                # SQLite transaction commits before any verified envelope is
                # released. A database failure is a rejection, never fallback
                # to the volatile cache.
                try:
                    claimed = self._durable_nonce_store.claim(
                        identity, nonce, ttl_seconds=self.replay_window_sec * 2
                    )
                except Exception as exc:
                    raise HardwareTransportError(
                        "HW_DURABLE_REPLAY_STORE_UNAVAILABLE", authenticated=True
                    ) from exc
                if not claimed:
                    raise HardwareTransportError(
                        "HW_REPLAY_NONCE_REUSED", authenticated=True
                    )
            else:
                self._claim_nonce(self._replay[identity], nonce)
        return VerifiedHardwareEnvelope(
            device_id=identity,
            kind=kind,
            timestamp=timestamp_text,
            nonce=nonce,
            payload=clean_payload,
        )

    def device_secret(self, device_id: str) -> str:
        identity = _validate_device_id(device_id)
        secret = self._keys.get(identity)
        if secret is None:
            raise HardwareTransportError("HW_DEVICE_NOT_ENROLLED")
        return secret

    def metadata(self) -> Dict[str, object]:
        with self._lock:
            return {
                "version": HARDWARE_TRANSPORT_VERSION,
                "enrolled_device_count": len(self._keys),
                "replay_window_sec": self.replay_window_sec,
                "replay_cache_entries_per_device": self.replay_cache_entries,
                "max_frame_bytes": self.max_frame_bytes,
                "direction_separated_keys": True,
                "auth_before_replay_cache_claim": True,
                "transport_confidentiality": False,
                "secret_values_exposed": False,
            }


class AuthenticatedLineFramer:
    """Bound one newline-delimited TCP frame while preserving fragmentation."""

    def __init__(self, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES):
        self.max_frame_bytes = min(1024 * 1024, max(1024, int(max_frame_bytes)))
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        if not isinstance(data, (bytes, bytearray)):
            raise HardwareTransportError("HW_FRAME_TYPE_INVALID")
        # Preserve the mainline preallocation bound for direct callers.
        if len(data) > self.max_frame_bytes:
            self._buffer.clear()
            raise HardwareTransportError("HW_FRAME_TOO_LARGE")
        frames: list[bytes] = []
        offset = 0
        delimiters = 0
        try:
            while offset < len(data):
                newline = data.find(b"\n", offset)
                end = len(data) if newline < 0 else newline
                if len(self._buffer) + end - offset > self.max_frame_bytes:
                    raise HardwareTransportError("HW_FRAME_TOO_LARGE")
                self._buffer.extend(memoryview(data)[offset:end])
                if newline < 0:
                    break
                delimiters += 1
                if delimiters > 256:
                    raise HardwareTransportError("HW_FRAME_BATCH_LIMIT_EXCEEDED")
                frame = bytes(self._buffer).strip()
                self._buffer.clear()
                if frame:
                    frames.append(frame)
                offset = newline + 1
        except HardwareTransportError:
            self._buffer.clear()
            raise
        return frames

    def reset(self) -> None:
        self._buffer.clear()


def validate_plaintext_hardware_host(host: str, *, allow_private_lan: bool = False) -> str:
    """Restrict unauthenticated-encryption TCP exposure.

    HMAC authenticates messages but does not encrypt telemetry. Therefore plain
    TCP is loopback-only unless a lab explicitly opts into a literal private or
    link-local address. Wildcard and public addresses are rejected either way.
    """
    value = str(host or "").strip()
    if value.lower() == "localhost":
        return value
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise HardwareTransportError("HW_HOST_LITERAL_REQUIRED") from exc
    if address.is_loopback:
        return value
    if address.is_unspecified or address.is_multicast or address.is_global:
        raise HardwareTransportError("HW_PLAINTEXT_PUBLIC_OR_WILDCARD_REJECTED")
    if allow_private_lan and (address.is_private or address.is_link_local):
        return value
    raise HardwareTransportError("HW_PLAINTEXT_LAN_DISABLED")


def parse_device_registry(raw: str) -> Dict[str, str]:
    """Parse a centrally policy-validated identity->secret registry defensively."""
    try:
        parsed = _strict_json_loads(str(raw or "{}"))
    except HardwareTransportError as exc:
        raise HardwareTransportError("HW_DEVICE_REGISTRY_INVALID") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise HardwareTransportError("HW_DEVICE_REGISTRY_REQUIRED")
    result: Dict[str, str] = {}
    for identity, secret in parsed.items():
        clean_id = _validate_device_id(str(identity))
        clean_secret = _validate_secret(str(secret))
        for prior in result.values():
            if hmac.compare_digest(clean_secret, prior):
                raise HardwareTransportError("HW_DEVICE_SECRET_REUSED")
        result[clean_id] = clean_secret
    return result
