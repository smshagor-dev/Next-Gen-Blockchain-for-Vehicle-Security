# PQC Hardware Provider Architecture

## Status

This document defines the activation boundary for hardware-backed ML-DSA-44 and ML-KEM-512 private keys in OmniGuard V2X.

The current production runtime remains `software_encrypted_file`. TPM2, PKCS#11, and HSM provider names are policy intents only until a concrete adapter passes the runtime capability probe and the main runtime is fully wired through the opaque operation boundary. No provider may report `hardware_backed=true` or `non_exportable=true` merely because a hardware provider name was configured.

The v3.0.3 hardening branch now contains the runtime-facing provider split:

- `native/pqc_active_operations.h`: provider-agnostic public state plus private `sign`/`decapsulate` operations;
- `native/pqc_software_active_operations.h`: the existing software provider implemented through the same private-operation interface;
- `native/pqc_sensitive_bytes.h`: move-only, zeroizing derived-secret storage;
- `native/pqc_hardware_provider.h`: non-exportable hardware provider contract and fail-closed capability probe.

`native/secure_blockchain_v303.cpp` still has to be switched from its legacy direct secret-vector operations to this interface before runtime hardware-backed PQC can be claimed.

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

## Runtime integration still required

The current `ActivePqcEngine` in `native/secure_blockchain_v303.cpp` still owns ML-DSA and ML-KEM software secret-key vectors and calls liboqs directly. The provider classes added during v3.0.3 make the intended replacement explicit, but the runtime switch is not complete yet.

The integration must:

- construct a `PqcActivePrivateOperations` implementation from the selected provider;
- route active signing through `sign_ml_dsa_44`;
- route active ML-KEM decapsulation through `decapsulate_ml_kem_512`;
- keep encapsulation and public signature verification local when appropriate;
- consume only `PqcActivePublicState` outside private-operation code;
- keep provider name, opaque key identifier, generation, public keys, and verified evidence metadata outside hardware;
- preserve mixed-generation historical ML-DSA verification through public trust history;
- keep historical ML-KEM claims explicitly non-authoritative unless the relevant protected private generation remains available.

Until this switch and at least one concrete hardware adapter are complete and validated on real hardware, OmniGuard must describe TPM2/PKCS#11/HSM support as fail-closed integration groundwork, not hardware-backed PQC key storage.

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
