# PQC Hardware Provider Architecture

## Status

This document defines the activation boundary for hardware-backed ML-DSA-44 and ML-KEM-512 private keys in OmniGuard V2X.

The current production provider remains `software_encrypted_file`. TPM2, PKCS#11, and HSM provider names are policy intents only until a concrete adapter passes the runtime capability probe and is selected by the runtime. No provider may report `hardware_backed=true` or `non_exportable=true` merely because a hardware provider name was configured.

The v3.0.3 runtime is now wired through the provider-facing private-operation split:

- `native/pqc_active_operations.h`: provider-agnostic public state plus private `sign`/`decapsulate` operations;
- `native/pqc_software_active_operations.h`: the existing software provider implemented through the same private-operation interface;
- `native/pqc_sensitive_bytes.h`: move-only, zeroizing derived-secret storage;
- `native/pqc_hardware_provider.h`: non-exportable hardware provider contract and fail-closed capability probe;
- `native/secure_blockchain_v303.cpp`: active ML-DSA signing and ML-KEM decapsulation are routed through `PqcActivePrivateOperations`; the main runtime no longer owns software private-key vectors or calls private-key liboqs sign/decapsulation APIs directly.

This completes the runtime operation-boundary refactor. It does **not** mean a TPM2, PKCS#11, or HSM adapter exists yet. Hardware-backed PQC must not be claimed until a concrete adapter is implemented and validated on real hardware.

## Standards baseline

The implementation target is the standardized post-quantum mechanism surface available in current hardware interfaces:

- PKCS #11 v3.2: ML-DSA and ML-KEM key generation and cryptographic operations.
- TPM 2.0 Library Specification v185: ML-DSA and ML-KEM support.
- NIST FIPS 203: ML-KEM.
- NIST FIPS 204: ML-DSA.

Support in a specification does not prove support in a particular token, TPM firmware, HSM, middleware version, or driver. Runtime capability evidence is mandatory.

## Provider contract

A concrete hardware provider must expose only:

1. public ML-DSA-44 and ML-KEM-512 key material;
2. opaque key identifiers;
3. ML-DSA-44 signing;
4. ML-KEM-512 decapsulation;
5. guarded rotation;
6. a runtime capability/evidence probe.

The interface intentionally contains no private-key export method. Private ML-DSA or ML-KEM bytes must never be returned to the main runtime or serialized into the software keystore format.

The derived ML-KEM shared secret is different from the non-exportable ML-KEM private key. The current protocol needs the derived secret transiently to validate `pqc_shared_secret_hash`; that value is represented by `PqcSensitiveBytes`, cannot be copied, exposes read-only bytes, and is zeroized on destruction.

## Activation gate

A provider can become active only when all of the following are true at runtime:

- backend/library loaded;
- target token/device present;
- selected mechanisms are hardware mechanisms, not software emulation;
- ML-DSA-44 key generation works;
- ML-DSA-44 signing works using an opaque private key;
- ML-KEM-512 key generation works;
- ML-KEM-512 decapsulation works using an opaque private key;
- private keys are enforced non-exportable;
- guarded rotation is supported;
- a stable device identity is available;
- a non-empty evidence reference is produced;
- ML-DSA signature, ML-KEM ciphertext, and shared-secret size metadata are supplied and validated.

Any missing requirement fails closed.

After activation, each hardware-backed private operation re-probes the provider. Device identity or required algorithm-size binding changes cause an immediate fail-closed error rather than continuing on a different token/device.

## Fallback policy

There is no implicit hardware-to-software fallback.

If `SMARTCAR_CPP_PQC_HARDWARE_REQUIRED=1`, startup must fail unless the selected hardware adapter completes the activation gate. An unavailable device, unsupported mechanism, missing middleware, failed login, failed evidence check, or missing opaque key must stop activation rather than create a software replacement key.

Software fallback may only be introduced behind a separate explicit operator policy. It must never be enabled automatically and must never preserve a `hardware_backed` claim after falling back.

## Runtime integration status

The native runtime operation boundary is integrated:

- active signing uses `PqcActivePrivateOperations::sign_ml_dsa_44`;
- active ML-KEM decapsulation uses `PqcActivePrivateOperations::decapsulate_ml_kem_512`;
- ML-KEM encapsulation and ML-DSA public verification remain local liboqs operations;
- the runtime consumes `PqcActivePublicState` for provider identity, public keys, algorithm sizes, and protection claims;
- software secret vectors live only inside `SoftwarePqcActivePrivateOperations` and are stored in zeroizing sensitive containers;
- mixed-generation historical ML-DSA verification remains based on public trust history;
- historical ML-KEM claims remain explicitly non-authoritative unless the relevant protected private generation is available.

The verification report exposes the active provider and protection truth-state. With the current software provider it must report software-backed, not non-exportable, while still confirming that the private-operation boundary is active.

Remaining hardware work is deliberately separate:

- implement at least one concrete TPM2 / PKCS#11 / HSM adapter;
- add runtime provider construction/selection for that concrete adapter;
- validate non-exportability, device identity, operation sizes, restart persistence, hot-swap detection, and guarded rotation on real hardware;
- only then allow a hardware provider to report `hardware_backed=true` and `non_exportable=true`.

Until those concrete adapter requirements are satisfied, OmniGuard must describe TPM2/PKCS#11/HSM support as fail-closed hardware integration groundwork, not deployed hardware-backed PQC key storage.

## Validation requirements for concrete adapters

A hardware adapter PR must include evidence from real hardware or a clearly identified hardware-backed service. Software tokens are useful for API compatibility tests but are not sufficient evidence for a hardware-backed claim.

Required validation includes:

- provider and firmware/middleware version capture;
- mechanism enumeration proving ML-DSA-44 and ML-KEM-512 support;
- non-exportability checks;
- key generation/sign/decapsulation functional tests;
- process restart persistence;
- device removal/unavailable fail-closed tests;
- wrong-token/wrong-slot and hot-swap tests;
- interrupted rotation tests;
- no-silent-fallback tests;
- public-key/key-id/provider/device consistency checks;
- audit evidence that contains no private key bytes, PINs, or session secrets.
