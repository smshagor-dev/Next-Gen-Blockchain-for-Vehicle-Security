"""Source-backed runtime security-strength posture for OmniGuard V2X.

This module intentionally avoids a fabricated percentage score.  It converts
observable runtime/security state into a conservative categorical posture:
STRONG, GUARDED, DEGRADED, or RISK.

The result is an operational dashboard signal only.  It is not a certification,
formal security proof, safety rating, or claim that the system is vulnerability-free.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping


STRENGTH_STRONG = "STRONG"
STRENGTH_GUARDED = "GUARDED"
STRENGTH_DEGRADED = "DEGRADED"
STRENGTH_RISK = "RISK"

CORE_METADATA_KEYS = (
    "security_capability",
    "identity_security",
    "consensus_security",
)


def _point_value(point: Any) -> tuple[Any, bool]:
    if not isinstance(point, Mapping):
        return None, False
    if point.get("status") in {"error", "unavailable"}:
        return point.get("value"), False
    if "value" not in point:
        return None, False
    return point.get("value"), True


def _metadata_available(point: Any) -> bool:
    value, ready = _point_value(point)
    return ready and isinstance(value, Mapping)


def _explicit_levels(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key in ("severity", "level", "risk"):
            raw = value.get(key)
            if isinstance(raw, str) and raw.strip():
                yield raw.strip().lower()
        for key in ("alerts", "items", "events"):
            if key in value:
                yield from _explicit_levels(value.get(key))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _explicit_levels(item)


def evaluate_security_strength(snapshot: Mapping[str, Any] | None) -> Dict[str, Any]:
    """Evaluate a conservative operational security posture from a live snapshot."""
    data: Mapping[str, Any] = snapshot if isinstance(snapshot, Mapping) else {}
    connection, connection_ready = _point_value(data.get("connection_status", {}))
    connection_text = str(connection).strip() if connection_ready else "Not Connected"

    levels: list[str] = []
    for key in ("alerts", "security_alerts", "runtime_alerts"):
        if key in data:
            levels.extend(_explicit_levels(data.get(key)))

    severe = {"critical", "high", "danger", "risk"}
    caution = {"medium", "warning", "warn", "degraded"}

    missing_core = [key for key in CORE_METADATA_KEYS if not _metadata_available(data.get(key, {}))]
    reasons: list[str] = []

    if any(level in severe for level in levels):
        level = STRENGTH_RISK
        reasons.append("explicit high/critical runtime security alert")
    elif not connection_ready or connection_text not in {"Connected", "Partial"}:
        level = STRENGTH_DEGRADED
        reasons.append("authenticated runtime connection unavailable")
    elif missing_core:
        level = STRENGTH_DEGRADED
        reasons.append("core security metadata unavailable: " + ", ".join(missing_core))
    elif connection_text == "Partial" or any(item in caution for item in levels):
        level = STRENGTH_GUARDED
        if connection_text == "Partial":
            reasons.append("runtime connection is partial")
        if any(item in caution for item in levels):
            reasons.append("explicit warning/medium security alert")
    else:
        level = STRENGTH_STRONG
        reasons.append("authenticated runtime connected with core security metadata available")

    summary = {
        STRENGTH_STRONG: "Authenticated runtime and core security sources healthy",
        STRENGTH_GUARDED: "Operational caution present; protections remain active",
        STRENGTH_DEGRADED: "Required runtime/security evidence is incomplete",
        STRENGTH_RISK: "Explicit high-risk runtime security signal present",
    }[level]

    return {
        "level": level,
        "summary": summary,
        "reasons": reasons,
        "connection": connection_text,
        "core_metadata_available": not missing_core,
        "missing_core_metadata": missing_core,
        "explicit_alert_levels": sorted(set(levels)),
        "source_backed": True,
        "numeric_score_synthesized": False,
        "certification_claim": False,
    }
