"""Bench-only physical actuation gate for OmniGuard V2X research hardware.

The gate is deliberately conservative. Real GPIO/CAN/serial actuation is off by
default and can be armed only for an explicitly configured bench session with a
local interlock file. This is an operational guardrail, not a certified safety
interlock and not a substitute for independent physical emergency-stop hardware.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional


INTERLOCK_VERSION = "OMNIGUARD_BENCH_INTERLOCK_V1"
INTERLOCK_CONTENT = "OMNIGUARD_BENCH_INTERLOCK_ARMED_V1"
_MAX_INTERLOCK_BYTES = 128


class HardwareSafetyError(RuntimeError):
    def __init__(self, reason: str):
        self.reason = str(reason)
        super().__init__(self.reason)


@dataclass(frozen=True)
class ActuationGateDecision:
    armed: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "armed": self.armed,
            "reason": self.reason,
            "bench_only": True,
            "physical_estop_required": True,
            "safety_certified": False,
        }


def _bool_value(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class BenchActuationGate:
    """Require explicit bench policy plus a secure local interlock file."""

    def __init__(self, environ: Optional[Mapping[str, str]] = None):
        self._env = environ if environ is not None else os.environ

    def _configured_path(self) -> Optional[Path]:
        raw = str(self._env.get("SMARTCAR_HARDWARE_BENCH_INTERLOCK_FILE", "")).strip()
        return Path(raw).expanduser() if raw else None

    def decision(self) -> ActuationGateDecision:
        if not _bool_value(self._env.get("SMARTCAR_HARDWARE_ACTUATION_ENABLED"), False):
            return ActuationGateDecision(False, "HARDWARE_ACTUATION_DISABLED")

        mode = str(self._env.get("SMARTCAR_HARDWARE_ACTUATION_MODE", "disabled")).strip().lower()
        if mode != "bench":
            return ActuationGateDecision(False, "HARDWARE_ACTUATION_MODE_NOT_BENCH")

        path = self._configured_path()
        if path is None:
            return ActuationGateDecision(False, "BENCH_INTERLOCK_FILE_REQUIRED")

        try:
            lst = path.lstat()
        except OSError:
            return ActuationGateDecision(False, "BENCH_INTERLOCK_FILE_UNAVAILABLE")
        if stat.S_ISLNK(lst.st_mode):
            return ActuationGateDecision(False, "BENCH_INTERLOCK_SYMLINK_REJECTED")
        if not stat.S_ISREG(lst.st_mode):
            return ActuationGateDecision(False, "BENCH_INTERLOCK_NOT_REGULAR_FILE")
        if lst.st_size <= 0 or lst.st_size > _MAX_INTERLOCK_BYTES:
            return ActuationGateDecision(False, "BENCH_INTERLOCK_FILE_SIZE_INVALID")

        # On POSIX, require ownership by the process user and reject group/world
        # writable permit files. Windows ACL validation remains an OS deployment
        # responsibility and is not claimed here.
        if os.name != "nt":
            if hasattr(os, "getuid") and lst.st_uid != os.getuid():
                return ActuationGateDecision(False, "BENCH_INTERLOCK_OWNER_INVALID")
            if lst.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return ActuationGateDecision(False, "BENCH_INTERLOCK_PERMISSIONS_INVALID")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= int(getattr(os, "O_NOFOLLOW"))
        try:
            fd = os.open(path, flags)
        except OSError:
            return ActuationGateDecision(False, "BENCH_INTERLOCK_OPEN_FAILED")
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                return ActuationGateDecision(False, "BENCH_INTERLOCK_NOT_REGULAR_FILE")
            if (opened.st_dev, opened.st_ino) != (lst.st_dev, lst.st_ino):
                return ActuationGateDecision(False, "BENCH_INTERLOCK_CHANGED_DURING_CHECK")
            raw = os.read(fd, _MAX_INTERLOCK_BYTES + 1)
        finally:
            os.close(fd)

        try:
            content = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            return ActuationGateDecision(False, "BENCH_INTERLOCK_CONTENT_INVALID")
        if content != INTERLOCK_CONTENT:
            return ActuationGateDecision(False, "BENCH_INTERLOCK_CONTENT_INVALID")
        return ActuationGateDecision(True, "BENCH_INTERLOCK_ARMED")

    def is_armed(self) -> bool:
        return self.decision().armed

    def require_armed(self) -> None:
        decision = self.decision()
        if not decision.armed:
            raise HardwareSafetyError(decision.reason)

    def metadata(self) -> dict[str, object]:
        decision = self.decision()
        return {
            "version": INTERLOCK_VERSION,
            "armed": decision.armed,
            "reason": decision.reason,
            "bench_only": True,
            "interlock_file_configured": self._configured_path() is not None,
            "requires_explicit_enable": True,
            "requires_physical_estop": True,
            "automatic_vehicle_actuation_default": False,
            "safety_certified": False,
        }
