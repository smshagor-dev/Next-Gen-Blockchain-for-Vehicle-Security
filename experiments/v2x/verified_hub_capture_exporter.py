"""Explicitly opt-in V2X hub research export, after real session verification.

The exporter writes ONLY canonical ALERT messages which have already passed
V2XHub's live session-MAC / sender-binding / replay validation. Its HMAC
integrity receipt covers all captured JSON fields, proving only possession of
the hub export key. Do not confuse this with independently rechecking a
sender's original session MAC from an offline file.

Contains sender-reported positions and pseudonyms. Enable only on a trusted
research bench under applicable data-handling rules. File is created with
mode 0600 and exclusive creation; raw research captures are never uploaded to
CI or committed. No physical actuator path uses this exporter.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from v2x_evidence_admission import AUTH_ID_RE, parse_evidence

EXPECTED_MESSAGE_FIELDS = {
    "type", "sender_id", "sender_type", "timestamp", "nonce", "payload", "security"
}


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


class VerifiedHubCaptureExporter:
    """One trusted hub process and one exclusive capture file per experiment."""

    def __init__(
        self, *, capture_path: Path, exporter_key_file: Path,
        source_id: str, scenario_id: str, seed: int,
    ):
        if (not isinstance(source_id, str) or not source_id
                or not isinstance(scenario_id, str) or not scenario_id
                or type(seed) is not int or seed < 0):
            raise ValueError("explicit source/scenario/seed required")
        capture_path = Path(capture_path)
        exporter_key_file = Path(exporter_key_file)
        if capture_path.is_symlink():
            raise ValueError("capture symlink is not permitted")
        if not capture_path.parent.is_dir():
            raise ValueError("capture parent directory must already exist")
        if not exporter_key_file.is_file() or exporter_key_file.is_symlink():
            raise ValueError("exporter key file must exist and not be a symlink")
        info = exporter_key_file.stat()
        if not 32 <= info.st_size <= 4096:
            raise ValueError("exporter key length must be between 32 and 4096 bytes")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("exporter key must be private to file owner (0600)")
        key = exporter_key_file.read_bytes()
        if len(key) < 32:
            raise ValueError("invalid exporter key")
        self.source_id = source_id
        self.scenario_id = scenario_id
        self.seed = seed
        self._key = key
        self._lock = threading.Lock()
        self._seq = 0
        self._closed = False
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(capture_path, flags, 0o600)
        self._stream = os.fdopen(fd, "wb", buffering=0)

    def record_verified(self, message: dict[str, Any], *, bound_sender_id: str) -> None:
        """Must be called after actual V2XHub.verify_message returns true."""
        if self._closed:
            raise RuntimeError("hub research capture exporter is closed")
        if (not isinstance(bound_sender_id, str)
                or not AUTH_ID_RE.fullmatch(bound_sender_id)):
            raise ValueError("invalid authenticated source binding")
        if not isinstance(message, dict) or set(message) != EXPECTED_MESSAGE_FIELDS:
            raise ValueError("unexpected V2X message structure for capture")
        if message.get("type") != "ALERT" or message.get("sender_id") != bound_sender_id:
            raise ValueError("capture requires bound ALERT session identity")
        if not isinstance(message.get("security"), dict):
            raise ValueError("signed session security envelope required")
        for name in ("session_id", "scheme", "signature"):
            if not isinstance(message["security"].get(name), str) or not message["security"][name]:
                raise ValueError("missing live verified security envelope")
        # This check also prevents arbitrary command fields piggybacking on
        # an otherwise valid report. It does not prove sensor honesty.
        capture_time = datetime.now(timezone.utc)
        parse_evidence(message["payload"], now=capture_time, max_age_sec=15)
        with self._lock:
            if self._closed:
                raise RuntimeError("hub research capture exporter is closed")
            seq = self._seq + 1
            bare = {
                "capture_id": secrets.token_hex(16),
                "source_id": self.source_id,
                "scenario_id": self.scenario_id,
                "seed": self.seed,
                "seq": seq,
                "received_at": capture_time.isoformat(),
                "session_verified": True,
                "bound_sender_id": bound_sender_id,
                "message": message,
            }
            record = dict(bare)
            record["export_mac"] = hmac.new(
                self._key, _canonical(bare), hashlib.sha256
            ).hexdigest()
            self._stream.write(_canonical(record) + b"\n")
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._seq = seq

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._stream.flush()
                    os.fsync(self._stream.fileno())
                finally:
                    self._stream.close()

    def __enter__(self) -> "VerifiedHubCaptureExporter":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()
