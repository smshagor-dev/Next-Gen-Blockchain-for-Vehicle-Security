"""Runtime factory for v2.9 incident response.

Construction is explicit: importing this module does not open files or require
incident-response credentials. A caller chooses when to create the manager in
the same process that owns the RuntimeSecurityMonitor.
"""

from __future__ import annotations

from typing import Optional

from env_config import get_env, get_int
from incident_response import IncidentEvidenceJournal, IncidentResponseManager
from key_provider import get_key_provider
from runtime_security_monitor import RuntimeSecurityMonitor, get_runtime_security_monitor


_STARTUP_PROBE = b"OMNIGUARD_INCIDENT_RESPONSE_STARTUP_CHECK_V1"


def create_runtime_incident_response_manager(
    monitor: Optional[RuntimeSecurityMonitor] = None,
) -> IncidentResponseManager:
    """Create a fail-closed environment-backed incident response manager.

    Both incident credential domains are exercised during construction so an
    empty journal cannot make a missing evidence/operator key look configured.
    The resulting probe MACs are deliberately discarded.
    """
    provider = get_key_provider()
    provider.hmac_sha256(
        "SMARTCAR_INCIDENT_EVIDENCE_KEY",
        _STARTUP_PROBE,
        purpose="incident-response-startup-check",
    )
    provider.hmac_sha256(
        "SMARTCAR_INCIDENT_OPERATOR_KEY",
        _STARTUP_PROBE,
        purpose="incident-response-startup-check",
    )

    runtime_monitor = monitor or get_runtime_security_monitor()
    journal = IncidentEvidenceJournal(
        get_env("SMARTCAR_INCIDENT_EVIDENCE_DIR", "logs/security"),
        provider,
        filename=get_env("SMARTCAR_INCIDENT_EVIDENCE_FILENAME", "incident-evidence.jsonl"),
        max_file_bytes=get_int("SMARTCAR_INCIDENT_EVIDENCE_MAX_BYTES", 64 * 1024 * 1024),
        max_record_bytes=get_int("SMARTCAR_INCIDENT_EVIDENCE_MAX_RECORD_BYTES", 16 * 1024),
    )
    return IncidentResponseManager(
        runtime_monitor,
        journal,
        provider,
        auth_window_sec=get_int("SMARTCAR_INCIDENT_OPERATOR_AUTH_WINDOW_SEC", 120),
        operator_nonce_cache_entries=get_int("SMARTCAR_INCIDENT_OPERATOR_NONCE_CACHE_ENTRIES", 1024),
        required_healthy_observations=get_int("SMARTCAR_INCIDENT_RECOVERY_HEALTHY_OBSERVATIONS", 3),
    )


def incident_response_runtime_metadata() -> dict[str, object]:
    """Return capability metadata without constructing a journal or exposing keys."""
    return {
        "policy": "OMNIGUARD_INCIDENT_RESPONSE_RUNTIME_V1",
        "construction": "explicit_same_process_factory",
        "startup_key_check": True,
        "uses_global_monitor_by_default": True,
        "automatic_recovery_allowed": False,
        "hardware_actuation_performed": False,
        "secret_values_exposed": False,
    }
