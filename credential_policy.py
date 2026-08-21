"""Central credential policy for OmniGuard V2X.

This module contains no project imports so env_config can safely use it as the
single enforcement point for secret quality, domain separation, registries, and
rotation-slot validation.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Tuple


@dataclass(frozen=True)
class SecretPolicy:
    domain: str
    min_length: int = 32


_SECRET_POLICIES: Dict[str, SecretPolicy] = {
    "SMARTCAR_PASSWORD": SecretPolicy("vehicle_password", 32),
    "SMARTCAR_AUTH_TOKEN": SecretPolicy("vehicle_auth", 32),
    "SMARTCAR_VALIDATOR_KEY": SecretPolicy("consensus_validator", 32),
    "SMARTCAR_SYNC_SHARED_KEY": SecretPolicy("sync_global", 32),
    "SMARTCAR_V2X_SHARED_SECRET": SecretPolicy("v2x_global", 32),
    "SMARTCAR_V2X_NODE_SECRET": SecretPolicy("v2x_node", 32),
    "SMARTCAR_HW_DEVICE_SECRET": SecretPolicy("hardware_device", 32),
    "SMARTCAR_GO_API_SECRET": SecretPolicy("control_api", 32),
    "SMARTCAR_RECOVERY_KEY": SecretPolicy("go_recovery", 32),
    "SMARTCAR_OWNER_RECOVERY_KEY": SecretPolicy("owner_recovery", 32),
    "SMARTCAR_STORAGE_PASSPHRASE": SecretPolicy("storage_encryption", 32),
    "SMARTCAR_FORENSIC_ACCESS_KEY": SecretPolicy("forensic_wrap", 32),
    "SMARTCAR_INSURANCE_ACCESS_KEY": SecretPolicy("insurance_wrap", 32),
    "SMARTCAR_INCIDENT_EVIDENCE_KEY": SecretPolicy("incident_evidence", 32),
    "SMARTCAR_INCIDENT_OPERATOR_KEY": SecretPolicy("incident_operator", 32),
}

_SECRET_REGISTRY_POLICIES: Dict[str, SecretPolicy] = {
    "SMARTCAR_POA_AUTHORITY_REGISTRY_JSON": SecretPolicy("consensus_validator", 32),
    "SMARTCAR_SYNC_VEHICLE_KEYS_JSON": SecretPolicy("sync_vehicle_registry", 32),
    "SMARTCAR_V2X_NODE_KEYS_JSON": SecretPolicy("v2x_node", 32),
    "SMARTCAR_HW_DEVICE_KEYS_JSON": SecretPolicy("hardware_device", 32),
}

_ROTATION_SUFFIX = "_PREVIOUS"
_UNSAFE_DEFAULT_FLAG = "SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS"

_WEAK_SECRET_VALUES = {
    "changeme",
    "change-me",
    "change_me",
    "default",
    "example",
    "password",
    "replace-me",
    "replace_me",
    "secret",
    "token",
    "your-secret-here",
    "your_secret_here",
}


def insecure_secret_defaults_allowed() -> bool:
    """Return whether the explicit lab-only compatibility bypass is enabled."""
    return os.getenv(_UNSAFE_DEFAULT_FLAG, "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _base_secret_name(name: str) -> str:
    if name.endswith(_ROTATION_SUFFIX):
        candidate = name[: -len(_ROTATION_SUFFIX)]
        if candidate in _SECRET_POLICIES:
            return candidate
    return name


def secret_policy(name: str) -> Optional[SecretPolicy]:
    return _SECRET_POLICIES.get(_base_secret_name(name))


def registry_policy(name: str) -> Optional[SecretPolicy]:
    return _SECRET_REGISTRY_POLICIES.get(name)


def is_sensitive_secret(name: str) -> bool:
    return secret_policy(name) is not None


def is_secret_registry(name: str) -> bool:
    return name in _SECRET_REGISTRY_POLICIES


def _normalized_secret(value: str) -> str:
    return value.strip().lower()


def validate_secret_value(name: str, value: str, min_length: Optional[int] = None) -> str:
    """Validate one secret without logging or returning derived material."""
    if value is None or not str(value).strip():
        raise RuntimeError(f"Sensitive credential {name} is not configured")

    value = str(value).strip()
    normalized = _normalized_secret(value)
    if normalized in _WEAK_SECRET_VALUES or normalized.startswith(
        ("example-", "changeme-", "replace-me-", "your-")
    ):
        raise RuntimeError(f"Sensitive credential {name} contains a placeholder value")

    policy = secret_policy(name)
    required = int(min_length if min_length is not None else (policy.min_length if policy else 32))
    required = max(1, required)
    if len(value) < required:
        raise RuntimeError(
            f"Sensitive credential {name} must contain at least {required} characters"
        )
    return value


def _configured_singleton_secrets(environ: Mapping[str, str]) -> Dict[str, str]:
    configured: Dict[str, str] = {}
    for env_name in _SECRET_POLICIES:
        raw = environ.get(env_name)
        if raw is not None and str(raw).strip():
            configured[env_name] = str(raw).strip()
        previous_name = env_name + _ROTATION_SUFFIX
        previous = environ.get(previous_name)
        if previous is not None and str(previous).strip():
            configured[previous_name] = str(previous).strip()
    return configured


def validate_secret_separation(
    name: str,
    value: str,
    environ: Optional[Mapping[str, str]] = None,
) -> None:
    """Reject exact secret reuse across distinct security domains."""
    policy = secret_policy(name)
    if policy is None:
        return

    env = environ if environ is not None else os.environ
    base = _base_secret_name(name)
    for other_name, other_value in _configured_singleton_secrets(env).items():
        if other_name == name:
            continue
        other_policy = secret_policy(other_name)
        if other_policy is None:
            continue
        other_base = _base_secret_name(other_name)

        if other_base == base:
            continue
        if policy.domain == other_policy.domain:
            continue
        if hmac.compare_digest(str(value).strip(), str(other_value).strip()):
            raise RuntimeError(
                f"Sensitive credential {name} reuses material from another security domain"
            )


def validate_secret_registry_json(
    name: str,
    raw: str,
    environ: Optional[Mapping[str, str]] = None,
) -> str:
    """Validate a JSON identity->secret trust registry and reject shared keys."""
    policy = registry_policy(name)
    if policy is None:
        return raw

    text = (raw or "").strip()
    if not text:
        return text
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Secret registry {name} must contain valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Secret registry {name} must be a JSON object")

    seen_values: Dict[str, str] = {}
    env = environ if environ is not None else os.environ
    singletons = _configured_singleton_secrets(env)

    for identity, secret in parsed.items():
        identity_text = str(identity).strip()
        if not identity_text:
            raise RuntimeError(f"Secret registry {name} contains an empty identity")
        secret_text = validate_secret_value(
            f"{name}[{identity_text}]",
            str(secret),
            min_length=policy.min_length,
        )
        for prior_secret in seen_values.values():
            if hmac.compare_digest(secret_text, prior_secret):
                raise RuntimeError(
                    f"Secret registry {name} reuses one credential across multiple identities"
                )
        seen_values[identity_text] = secret_text

        for singleton_name, singleton_value in singletons.items():
            singleton_policy = secret_policy(singleton_name)
            if singleton_policy is None or singleton_policy.domain == policy.domain:
                continue
            if hmac.compare_digest(secret_text, singleton_value):
                raise RuntimeError(
                    f"Secret registry {name} reuses material from another security domain"
                )
    return raw


def validate_rotation_pair(name: str, current: str, previous: Optional[str]) -> Tuple[str, ...]:
    """Validate current + optional previous secret slots for controlled rotation."""
    current_value = validate_secret_value(name, current)
    validate_secret_separation(name, current_value)
    if previous is None or not str(previous).strip():
        return (current_value,)

    previous_name = name + _ROTATION_SUFFIX
    previous_value = validate_secret_value(previous_name, str(previous))
    validate_secret_separation(previous_name, previous_value)
    if hmac.compare_digest(current_value, previous_value):
        raise RuntimeError(
            f"Rotation slots {name} and {previous_name} must not contain the same credential"
        )
    return (current_value, previous_value)


def credential_policy_metadata(environ: Optional[Mapping[str, str]] = None) -> Dict[str, object]:
    """Return non-secret policy state suitable for diagnostics."""
    env = environ if environ is not None else os.environ
    configured = []
    previous_slots = []
    for name in sorted(_SECRET_POLICIES):
        if str(env.get(name, "")).strip():
            configured.append(name)
        if str(env.get(name + _ROTATION_SUFFIX, "")).strip():
            previous_slots.append(name + _ROTATION_SUFFIX)
    configured_registries = [
        name
        for name in sorted(_SECRET_REGISTRY_POLICIES)
        if str(env.get(name, "")).strip() not in {"", "{}"}
    ]
    return {
        "policy": "OMNIGUARD_CREDENTIAL_POLICY_V2_4",
        "strict_defaults": not insecure_secret_defaults_allowed(),
        "configured_secret_names": configured,
        "configured_previous_slots": previous_slots,
        "configured_registry_names": configured_registries,
        "secret_values_exposed": False,
    }
