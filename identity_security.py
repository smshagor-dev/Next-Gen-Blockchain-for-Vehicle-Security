# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
"""Identity authenticity and admission-policy metadata for v2.6.

Lamport/DID proves possession of signing secrets. Network admission is a
separate control and is fail-closed unless an explicit policy and enrollment
registry are configured. OPEN_REGISTRATION remains available only as an
explicit lab choice and never implies Sybil resistance.
"""

import json
import os

OPEN_REGISTRATION = "OPEN_REGISTRATION"
DENY_UNCONFIGURED = "DENY_UNCONFIGURED"
PROOF_OF_STAKE = "PROOF_OF_STAKE"
PROOF_OF_WORK = "PROOF_OF_WORK"
CERTIFICATE_AUTHORITY = "CERTIFICATE_AUTHORITY"
VEHICLE_MANUFACTURER_REGISTRY = "VEHICLE_MANUFACTURER_REGISTRY"
TRANSPORT_AUTHORITY_REGISTRY = "TRANSPORT_AUTHORITY_REGISTRY"

IDENTITY_ADMISSION_POLICIES = {
    OPEN_REGISTRATION,
    DENY_UNCONFIGURED,
    PROOF_OF_STAKE,
    PROOF_OF_WORK,
    CERTIFICATE_AUTHORITY,
    VEHICLE_MANUFACTURER_REGISTRY,
    TRANSPORT_AUTHORITY_REGISTRY,
}

IMPLEMENTED_REGISTRY_POLICIES = {
    CERTIFICATE_AUTHORITY,
    VEHICLE_MANUFACTURER_REGISTRY,
    TRANSPORT_AUTHORITY_REGISTRY,
}

OPEN_REGISTRATION_SYBIL_WARNING = "No Sybil-resistance guarantee. Unlimited identities may be created."
UNCONFIGURED_WARNING = "Identity admission is not fully configured; network admission must fail closed."


def get_identity_admission_policy() -> str:
    raw = os.getenv("SMARTCAR_IDENTITY_ADMISSION_POLICY")
    if raw is None or not raw.strip():
        return DENY_UNCONFIGURED
    policy = raw.strip().upper()
    return policy if policy in IDENTITY_ADMISSION_POLICIES else DENY_UNCONFIGURED


def _admission_registry_count() -> int:
    try:
        raw = os.getenv("SMARTCAR_SYNC_VEHICLE_KEYS_JSON", "{}") or "{}"
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return 0
        return len([identity for identity, secret in parsed.items() if str(identity).strip() and str(secret).strip()])
    except Exception:
        return 0


def identity_security_metadata(policy: str = "") -> dict:
    effective_policy = (policy or get_identity_admission_policy()).strip().upper()
    if effective_policy not in IDENTITY_ADMISSION_POLICIES:
        effective_policy = DENY_UNCONFIGURED

    registry_count = _admission_registry_count()
    registry_configured = registry_count > 0
    explicit_open = effective_policy == OPEN_REGISTRATION
    implemented = effective_policy in IMPLEMENTED_REGISTRY_POLICIES and registry_configured
    admission_enforced = implemented or effective_policy == DENY_UNCONFIGURED
    sybil_resistant = implemented

    metadata = {
        "identity_authenticity": True,
        "identity_admission_policy": effective_policy,
        "enforcement_layer": "python_sync_network",
        "identity_admission_enforced": admission_enforced,
        "admission_registry_configured": registry_configured,
        "admission_registry_identity_count": registry_count,
        "open_registration_explicit_only": True,
        "default_fail_closed": True,
        "sybil_resistance": sybil_resistant,
        "identity_authenticity_model": {
            "secret_key_ownership": True,
            "valid_signatures": True,
            "non_repudiation": True,
        },
        "sybil_resistance_model": (
            "Network identities are limited to an explicitly enrolled per-identity registry."
            if sybil_resistant
            else OPEN_REGISTRATION_SYBIL_WARNING if explicit_open else UNCONFIGURED_WARNING
        ),
        "secret_values_exposed": False,
    }
    if not sybil_resistant:
        metadata["warning"] = (
            OPEN_REGISTRATION_SYBIL_WARNING if explicit_open else UNCONFIGURED_WARNING
        )
    if effective_policy in {PROOF_OF_STAKE, PROOF_OF_WORK}:
        metadata["warning"] = "Selected admission policy is not implemented by the current sync admission layer; admission must fail closed."
        metadata["identity_admission_enforced"] = True
    if effective_policy in IMPLEMENTED_REGISTRY_POLICIES and not registry_configured:
        metadata["warning"] = "Selected registry admission policy has no enrolled identities; admission must fail closed."
        metadata["identity_admission_enforced"] = True
    return metadata
