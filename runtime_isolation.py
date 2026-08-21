"""Runtime child-process isolation helpers for OmniGuard V2X."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Mapping, MutableMapping, Optional, Set


_BLOCKED_ENV_NAMES = {
    "PYTHONPATH",
    "PYTHONHOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
}


@dataclass(frozen=True)
class RuntimeIsolationAudit:
    timestamp: str
    child_kind: str
    inherited_environment_count: int
    stripped_smartcar_count: int
    stripped_injection_count: int
    allowed_smartcar_names: tuple[str, ...]
    close_fds: bool
    detached_session: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "child_kind": self.child_kind,
            "inherited_environment_count": self.inherited_environment_count,
            "stripped_smartcar_count": self.stripped_smartcar_count,
            "stripped_injection_count": self.stripped_injection_count,
            "allowed_smartcar_names": list(self.allowed_smartcar_names),
            "close_fds": self.close_fds,
            "detached_session": self.detached_session,
            "secret_values_exposed": False,
        }


def build_isolated_child_environment(
    base_environment: Optional[Mapping[str, str]] = None,
    *,
    smartcar_overrides: Optional[Mapping[str, str]] = None,
    allowed_smartcar_names: Optional[Set[str]] = None,
    child_kind: str = "go-control-backend",
) -> tuple[Dict[str, str], RuntimeIsolationAudit]:
    """Return a child environment with project secrets stripped by default."""
    base = base_environment if base_environment is not None else os.environ
    allowed = set(allowed_smartcar_names or set())
    overrides = dict(smartcar_overrides or {})

    result: MutableMapping[str, str] = {}
    stripped_smartcar = 0
    stripped_injection = 0

    for key, value in base.items():
        name = str(key)
        if name.startswith("SMARTCAR_"):
            if name in allowed:
                result[name] = str(value)
            else:
                stripped_smartcar += 1
            continue
        if name in _BLOCKED_ENV_NAMES or name.startswith("DYLD_"):
            stripped_injection += 1
            continue
        result[name] = str(value)

    for key, value in overrides.items():
        name = str(key)
        if not name.startswith("SMARTCAR_"):
            raise ValueError("runtime isolation overrides may only set SMARTCAR_* values")
        if name not in allowed:
            raise ValueError(f"runtime isolation override {name} is not in the allow-list")
        result[name] = str(value)

    detached = os.name != "nt"
    audit = RuntimeIsolationAudit(
        timestamp=datetime.now(timezone.utc).isoformat(),
        child_kind=str(child_kind),
        inherited_environment_count=len(result),
        stripped_smartcar_count=stripped_smartcar,
        stripped_injection_count=stripped_injection,
        allowed_smartcar_names=tuple(sorted(allowed)),
        close_fds=True,
        detached_session=detached,
    )
    return dict(result), audit


def subprocess_isolation_kwargs() -> Dict[str, object]:
    """Portable subprocess flags that reduce descriptor/session inheritance."""
    kwargs: Dict[str, object] = {"close_fds": True}
    if os.name == "nt":
        flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        flags |= int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    return kwargs


def runtime_isolation_metadata(audit: Optional[RuntimeIsolationAudit] = None) -> Dict[str, object]:
    result: Dict[str, object] = {
        "policy": "OMNIGUARD_RUNTIME_ISOLATION_V1",
        "smartcar_environment_default": "deny",
        "injection_environment_stripped": sorted(_BLOCKED_ENV_NAMES),
        "close_fds": True,
        "posix_detached_session": True,
        "os_privilege_drop": False,
        "sandbox_or_seccomp": False,
        "hardware_attestation": False,
        "secret_values_exposed": False,
    }
    if audit is not None:
        result["last_spawn"] = audit.to_dict()
    return result
