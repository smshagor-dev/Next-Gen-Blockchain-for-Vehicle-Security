# Phase 1 — Security Baseline and Trust Foundation

Branch: `security/v2.1-zero-trust-hardening`

## Goal

Establish a fail-closed security baseline before deeper V2X, consensus, ledger, and backend hardening. The goal is to remove repository-level credential exposure, make secret loading safer, and create enforceable regression tests for configuration handling.

## Implemented in this phase

### 1. Secret hygiene

- Remove the tracked `.env` file from the hardening branch.
- Add `.env` and local environment variants to `.gitignore`.
- Add a sanitized `.env.example` containing no usable credentials.
- Document that every secret previously committed must be rotated.

### 2. Safer environment parsing

`env_config.py` now:

- preserves literal `#` characters inside unquoted secrets such as `abc#123`;
- treats `#` as an inline comment only when it is separated by whitespace;
- preserves quoted values containing `#`;
- rejects malformed environment variable names;
- ignores malformed quoted values instead of partially loading them;
- provides `get_required_env()` for fail-closed required configuration;
- provides `get_required_secret()` with placeholder and minimum-length checks.

### 3. Repository hygiene

- Ignore Python caches, test caches, logs, build products, temporary files, IDE metadata, and local virtual environments.
- Remove tracked root `__pycache__` content from the hardening branch.

### 4. Security regression tests

Add focused tests for:

- literal `#` preservation;
- inline comment parsing;
- quoted values;
- invalid variable names;
- malformed quotes;
- required-secret rejection for missing, placeholder, and short values;
- required-secret acceptance for sufficiently strong values.

## Manual actions still required

These cannot be made safe by a source-code commit alone:

1. Rotate every secret that has ever been committed to this repository.
2. Purge historical secret blobs using an approved history-rewrite procedure.
3. Invalidate any downstream credentials derived from the exposed material.
4. Enable branch protection and required CI checks on `main`.
5. Configure private vulnerability reporting.
6. Move production secrets to a secret manager / hardware-backed store.

## Next hardening step

After this baseline is green, Phase 1 continues with trust binding:

- remove hard-coded protocol secrets and fail closed when required secrets are absent;
- bind authenticated sessions to vehicle identities;
- bind consensus votes to authenticated validator identities;
- require message authentication whenever a session exists;
- add replay protection using timestamp windows, nonces, and sequence numbers.
