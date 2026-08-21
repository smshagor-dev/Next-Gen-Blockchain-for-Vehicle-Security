"""Canonical release metadata for OmniGuard V2X.

The repository-level VERSION file is the source of truth for the public release
number. Internal hardening phases may use a different engineering phase label;
that mapping is exposed explicitly so public release numbering cannot silently
drift from implementation history.
"""

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
INTERNAL_HARDENING_PHASE = "v3.2"
RELEASE_NAME = "Native Cryptographic Modernization & Real-PQC Validation"
RELEASE_CHANNEL = "research_hardening"


def release_metadata() -> Dict[str, object]:
    """Return non-secret, conservative release/build identity metadata."""
    return {
        "release_version": RELEASE_VERSION,
        "release_series": RELEASE_SERIES,
        "release_name": RELEASE_NAME,
        "release_channel": RELEASE_CHANNEL,
        "internal_hardening_phase": INTERNAL_HARDENING_PHASE,
        "real_pqc_native_validation": True,
        "native_data_at_rest": "AES-256-GCM",
        "native_signature": "ML-DSA-44",
        "native_key_encapsulation": "ML-KEM-512",
        "production_certified": False,
        "vehicle_safety_certified": False,
        "secret_values_exposed": False,
    }
