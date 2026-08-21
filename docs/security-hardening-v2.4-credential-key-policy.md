# v2.4 Credential & Key Hardening

## Goal

Prevent OmniGuard V2X from silently starting with embedded, reused, placeholder, or weak credential material.

This phase centralizes enforcement in `env_config.py` + `credential_policy.py` so direct core users, dashboards, sync/V2X components, and the authenticated Go adapter all inherit the same fail-closed policy when they use environment-backed secrets.

## Fail-closed secret defaults

Security-sensitive `get_env()` lookups no longer accept a non-empty caller-provided fallback when the corresponding environment variable is missing.

Affected credential domains include:

- vehicle password
- vehicle authentication token
- PoA validator key
- sync shared key
- V2X global/node secrets
- Python <-> Go control API secret
- Go recovery key
- Python owner recovery key
- storage-encryption passphrase
- forensic key-wrap secret
- insurance key-wrap secret

A controlled lab can explicitly set `SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS=1`, but that disables this protection and must not be used as a deployment default.

## Secret quality

Configured sensitive credentials are rejected when they are:

- blank;
- shorter than the configured minimum (32 characters for the current policy);
- common placeholders such as `changeme`, `default`, `password`, `secret`, or equivalent prefixed examples.

No secret value is written to policy metadata or diagnostic output.

## Domain separation

The credential policy compares configured singleton secret values and rejects exact reuse across distinct security domains.

Examples of reuse that are rejected include using one value simultaneously for:

- auth token and recovery key;
- validator key and control-API secret;
- vehicle password and storage passphrase;
- forensic and insurance wrapping keys;
- sync and V2X keys.

This reduces blast radius when one credential is exposed.

## Trust-registry validation

The following identity->secret JSON registries are validated centrally:

- `SMARTCAR_POA_AUTHORITY_REGISTRY_JSON`
- `SMARTCAR_SYNC_VEHICLE_KEYS_JSON`
- `SMARTCAR_V2X_NODE_KEYS_JSON`

Validation rejects:

- invalid JSON;
- non-object registry values;
- blank identities;
- short/placeholder secrets;
- reuse of one credential for multiple identities;
- reuse of registry material across a different configured security domain.

Same-domain use remains possible where a local singleton represents one identity also present in its trust registry.

## Rotation foundation

`env_config.get_secret_ring()` provides an explicit current + optional previous-secret interface:

- current variable: `NAME`
- previous rotation slot: `NAME_PREVIOUS`

The two values must be distinct and both pass credential validation.

This helper is only a foundation. A protocol does not become rotation-aware merely because a `*_PREVIOUS` value exists. Protocol code must deliberately verify old traffic against the returned ring and sign all new traffic with `ring[0]`.

That keeps rotation behavior explicit instead of silently widening trust.

## Configuration migration

The `.env.example` now lists independent credentials for storage, owner recovery, forensic access, insurance access, dashboard/runtime password, auth, consensus, sync, Go control, and Go recovery.

Generate each value independently. Do not copy one generated token into multiple fields.

Previously committed secrets remain compromised even after this runtime policy is merged. They still require rotation and an approved Git-history purge.

## Validation

The v2.4 regression suite checks:

- sensitive fallback rejection;
- explicit lab-only bypass behavior;
- secret quality enforcement;
- cross-domain duplicate rejection;
- independent-domain acceptance;
- current/previous rotation-slot validation;
- duplicate trust-registry key rejection;
- registry quality enforcement;
- non-secret diagnostics.

The Security Baseline workflow compiles the credential-policy module and runs this suite alongside all previously added sync, DID, V2X, control-API, ledger, and Go validations.

## Security boundary

This phase reduces credential misuse and accidental key reuse. It does not provide hardware-backed key storage, OS-level process isolation, TPM attestation, HSM-backed signing, or automatic online key rotation. Those remain later hardening stages.
