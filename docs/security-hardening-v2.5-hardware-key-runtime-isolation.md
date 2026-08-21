# v2.5 Hardware-Key Foundation and Runtime Isolation

## Status

Research security-hardening phase. This phase reduces credential exposure and
creates an explicit key-provider boundary. It is **not** a claim that TPM/HSM
protection, OS sandboxing, or vehicle-safety certification is complete.

## Key-provider boundary

`key_provider.py` introduces a provider contract with explicit capabilities:

- provider name;
- hardware-backed or software-backed;
- exportable or non-exportable key material;
- HMAC-SHA256 operation support;
- bounded value-free key-access audit metadata.

The currently implemented provider is `environment`. It is software-backed and
exportable. Secret values still originate in the process environment.

Configured provider names `tpm2`, `pkcs11`, and `hsm` intentionally fail closed
until a real runtime adapter is installed. They never silently fall back to the
environment provider.

`SMARTCAR_REQUIRE_HARDWARE_KEY_PROVIDER=1` rejects the environment provider.
This makes deployment policy explicit even before a hardware adapter exists.

## Best-effort memory handling

`SecretBuffer` stores its owned copy in a mutable `bytearray` and overwrites it
on close/context exit. Key-provider HMAC operations use that mutable buffer
directly to avoid an additional immutable key copy.

This does **not** guarantee complete erasure from Python memory. Environment
strings, interpreter temporaries, legacy APIs that require text, OS process
memory, swap, crash capture, and third-party libraries may still create copies.
The implementation therefore reports this as best-effort zeroization only.

`env_config.py` routes sensitive `get_env()` / `get_required_secret()` /
rotation-slot access through the process key provider. Legacy callers still
receive a Python string where their API requires one, but the provider-owned
mutable copy is zeroized immediately after export.

## Value-free key access audit

Key access events record only:

- timestamp;
- provider name;
- credential **name**;
- operation;
- purpose;
- success/failure.

No credential value, derived key, HMAC input, or HMAC result is stored in the
audit metadata.

## Python launcher isolation

The normal `main.py` entrypoint installs `runtime_backend_patch.py` before the
dashboard constructs a backend.

The Go backend child receives a deny-by-default `SMARTCAR_*` environment. The
allow-list is limited to:

- `SMARTCAR_GO_API_SECRET`;
- `SMARTCAR_GO_DATA_DIR`;
- `SMARTCAR_GO_ALLOW_CLASSICAL_ECDH_FALLBACK`;
- `SMARTCAR_IDENTITY_ADMISSION_POLICY`.

Unrelated project credentials such as auth, validator, sync, V2X, owner
recovery, forensic, and insurance keys are not forwarded by the hardened main
launcher.

The launcher also strips common interpreter/loader injection variables including
`PYTHONPATH`, `PYTHONHOME`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, and `DYLD_*` from the
Go child environment. File descriptors are closed on spawn. POSIX children start
in a new session; Windows uses no-window/new-process-group flags when available.

## Go self-hardening

The Go package applies a second defense-in-depth environment sanitizer at
startup, so direct Go launches do not retain unrelated `SMARTCAR_*` secrets.

On supported Unix targets the Go process applies:

- `umask 0077` for private-by-default file creation;
- core-dump limit `0`.

On Linux it also requests `PR_SET_NO_NEW_PRIVS`. This is best-effort and is not a
replacement for namespaces, seccomp, AppContainer, containers, SELinux, or
systemd sandbox directives.

## Known limitations

This phase does not yet implement:

- TPM 2.0 key creation/sealing/unsealing;
- PKCS#11 sessions or HSM object handles;
- non-exportable signing for all current protocols;
- remote attestation or measured boot;
- mlock/VirtualLock protection against swapping;
- guaranteed Python heap zeroization;
- Linux namespaces/seccomp or Windows AppContainer;
- dedicated unprivileged service account creation;
- automatic online key rotation.

The Go control API currently requires an exportable shared secret, so a future
hardware adapter must either provide a compatible non-exportable MAC operation
on both sides or replace that transport with a hardware-bound authenticated IPC
scheme.

## Validation

The v2.5 regression suite covers:

- mutable secret-buffer zeroization;
- value-free audit output;
- environment-provider HMAC correctness;
- hardware-required fail-closed policy;
- unavailable hardware-adapter fail-closed behavior;
- cross-domain key-reuse rejection through the provider;
- launcher child-environment allow-listing;
- loader/interpreter injection-variable removal;
- closed descriptor/session spawn policy;
- Go startup removal of unrelated project credentials;
- Go startup removal of injection variables;
- retention of explicitly allowed non-secret Go policy values.

All earlier sync, DID/Lamport, V2X, control-API, credential-policy, ledger, and Go
security regressions remain required by the hosted Security Baseline workflow.
