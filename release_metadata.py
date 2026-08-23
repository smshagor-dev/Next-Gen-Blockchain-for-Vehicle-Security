"""Canonical release metadata for OmniGuard V2X."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_VERSION_FILE = Path(__file__).resolve().with_name("VERSION")


def _load_release_version() -> str:
    try:
        value = _VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("canonical VERSION file is unavailable") from exc
    if not _VERSION_RE.fullmatch(value):
        raise RuntimeError("canonical VERSION file must contain semantic version X.Y.Z")
    return value


RELEASE_VERSION = _load_release_version()
RELEASE_SERIES = ".".join(RELEASE_VERSION.split(".")[:2])
INTERNAL_HARDENING_PHASE = "v4.0"
RELEASE_NAME = "Unified Security Runtime, Post-Quantum Trust & Live Operations"
RELEASE_CHANNEL = "research_hardening"


def release_metadata() -> Dict[str, object]:
    return {
        "release_version": RELEASE_VERSION,
        "release_series": RELEASE_SERIES,
        "release_name": RELEASE_NAME,
        "release_channel": RELEASE_CHANNEL,
        "internal_hardening_phase": INTERNAL_HARDENING_PHASE,
        "cumulative_security_line_from": "2.0.1",
        "real_pqc_native_validation": True,
        "durable_pqc_identity": True,
        "signed_pqc_key_transitions": True,
        "mixed_generation_ledger_verification": True,
        "authenticated_local_rollback_anchor": True,
        "hardware_monotonic_rollback_protection": False,
        "hardware_pqc_provider_implemented": True,
        "pkcs11_v32_provider_adapter_implemented": True,
        "pkcs11_production_token_validated": False,
        "tpm2_pqc_provider_implemented": False,
        "generic_hsm_pqc_provider_implemented": False,
        "native_data_at_rest": "AES-256-GCM",
        "native_signature": "ML-DSA-44",
        "native_key_encapsulation": "ML-KEM-512",
        "authenticated_go_control_api": True,
        "authenticated_live_runtime_stream": True,
        "live_runtime_loopback_only": True,
        "live_runtime_hmac_authenticated": True,
        "non_destructive_live_dashboard_feeds": True,
        "source_backed_runtime_security_strength": True,
        "source_backed_dashboard_values": True,
        "release_integrity_manifest": True,
        "deterministic_sbom_and_provenance": True,
        "current_tree_secret_scan": True,
        "windows_runtime_smoke": True,
        "production_certified": False,
        "vehicle_safety_certified": False,
        "secret_values_exposed": False,
    }
