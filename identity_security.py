# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
"""Identity authenticity and admission-policy metadata.

Lamport DID verification proves ownership of the corresponding signing secrets.
It does not limit identity creation and therefore does not provide Sybil
resistance under open registration.
"""

from env_config import get_env

OPEN_REGISTRATION = "OPEN_REGISTRATION"
PROOF_OF_STAKE = "PROOF_OF_STAKE"
PROOF_OF_WORK = "PROOF_OF_WORK"
CERTIFICATE_AUTHORITY = "CERTIFICATE_AUTHORITY"
VEHICLE_MANUFACTURER_REGISTRY = "VEHICLE_MANUFACTURER_REGISTRY"
TRANSPORT_AUTHORITY_REGISTRY = "TRANSPORT_AUTHORITY_REGISTRY"

IDENTITY_ADMISSION_POLICIES = {
    OPEN_REGISTRATION,
    PROOF_OF_STAKE,
    PROOF_OF_WORK,
    CERTIFICATE_AUTHORITY,
    VEHICLE_MANUFACTURER_REGISTRY,
    TRANSPORT_AUTHORITY_REGISTRY,
}

OPEN_REGISTRATION_SYBIL_WARNING = "No Sybil-resistance guarantee. Unlimited identities may be created."


def get_identity_admission_policy() -> str:
    policy = get_env("SMARTCAR_IDENTITY_ADMISSION_POLICY", OPEN_REGISTRATION).strip().upper()
    return policy if policy in IDENTITY_ADMISSION_POLICIES else OPEN_REGISTRATION


def identity_security_metadata(policy: str = "") -> dict:
    effective_policy = (policy or get_identity_admission_policy()).strip().upper()
    if effective_policy not in IDENTITY_ADMISSION_POLICIES:
        effective_policy = OPEN_REGISTRATION
    sybil_resistant = effective_policy != OPEN_REGISTRATION
    metadata = {
        "identity_authenticity": True,
        "sybil_resistance": sybil_resistant,
        "identity_admission_policy": effective_policy,
        "identity_authenticity_model": {
            "secret_key_ownership": True,
            "valid_signatures": True,
            "non_repudiation": True,
        },
        "sybil_resistance_model": (
            "Identity creation is limited by an external admission policy."
            if sybil_resistant
            else OPEN_REGISTRATION_SYBIL_WARNING
        ),
    }
    if not sybil_resistant:
        metadata["warning"] = OPEN_REGISTRATION_SYBIL_WARNING
    return metadata
