# PQC Hardware Provider Architecture

## Status

This document defines the activation boundary for hardware-backed ML-DSA-44 and ML-KEM-512 private keys in OmniGuard V2X.

The current production code path remains `software_encrypted_file`. TPM2, PKCS#11, and HSM provider names are policy intents only until a concrete adapter passes the runtime capability probe. No provider may report `hardware_backed=true` or `non_exportable=true` merely because a hardware provider name was configured.

## Standards baseline

The implementation target is the standardized post-quantum mechanism surface available in current hardware interfaces:

- PKCS #11 v3.2: ML-DSA and ML-KEM key generation and cryptographic operations.
- TPM 2.0 Library Specification v185: ML-DSA and ML-KEM support.
- NIST FIPS 203: ML-KEM.
- NIST FIPS 204: ML-DSA.

Support in a specification does not prove support in a particular token, TPM firmware, HSM, middleware version, or driver. Runtime capability evidence is mandatory.

## Provider contract

`native/pqc_hardware_provider.h` is the non-exportable provider boundary.

A concrete provider must expose only:

1. public ML-DSA-44 and ML-KEM-512 key material;
2. opaque key identifiers;
3. ML-DSA-44 signing;
4. ML-KEM-512 decapsulation;
5. guarded rotation;
6. a runtime capability/evidence probe.

The interface intentionally contains no private-key export method. Private ML-DSA or ML-KEM bytes must never be returned to the main runtime or serialized into the software keystore format.

## Activation gate

A provider can become active only when all of the following are true at runtime:

- backend/library loaded;
- target token/device present;
- the selected mechanisms are hardware mechanisms, not software emulation;
- ML-DSA-44 key generation works;
- ML-DSA-44 signing works using an opaque private key;
- ML-KEM-512 key generation works;
- ML-KEM-512 decapsulation works using an opaque private key;
- private keys are marked/enforced non-exportable;
- guarded rotation is supported;
- a stable device identity is available;
- a non-empty evidence reference is produced for the successful probe.

Any missing requirement fails closed.

## Fallback policy

There is no implicit hardware-to-software fallback.

If `SMARTCAR_CPP_PQC_HARDWARE_REQUIRED=1`, startup must fail unless the selected hardware adapter completes the activation gate. An unavailable device, unsupported mechanism, missing middleware, failed login, failed attestation/evidence check, or missing opaque key must stop activation rather than create a software replacement key.

Software fallback may only be introduced later behind a separate explicit operator policy. It must never be enabled automatically and must never preserve a `hardware_backed` claim after falling back.

## Runtime refactor required for a real adapter

The current `ActivePqcEngine` owns ML-DSA and ML-KEM secret-key vectors and calls liboqs directly. A real non-exportable provider therefore requires a second integration step:

- move active signing behind the provider operation boundary;
- move active ML-KEM decapsulation behind the provider operation boundary;
- keep encapsulation and public verification local when appropriate;
- store only provider name, opaque key identifier, generation, public keys, and verified evidence metadata outside hardware;
- update rotation/trust-keyring transitions to use provider operations instead of exported secret vectors;
- preserve mixed-generation historical ML-DSA verification using public trust history;
- keep historical ML-KEM claims explicitly non-authoritative unless the relevant private generation remains available through a protected provider.

Until that refactor and at least one concrete hardware adapter are complete and validated on real hardware, OmniGuard must continue to describe TPM2/PKCS#11/HSM support as fail-closed integration groundwork, not hardware-backed PQC key storage.

## Validation requirements for concrete adapters

A hardware adapter PR must include evidence from real hardware or a clearly identified hardware-backed service. Software tokens are useful for API compatibility tests but are not sufficient evidence for a hardware-backed claim.

Required validation includes:

- provider and firmware/middleware version capture;
- mechanism enumeration proving ML-DSA-44 and ML-KEM-512 support;
- non-exportability checks;
- key generation/sign/decapsulation functional tests;
- process restart persistence;
- device removal/unavailable fail-closed tests;
- wrong-token/wrong-slot tests;
- interrupted rotation tests;
- no-silent-fallback tests;
- public-key/key-id consistency checks;
- audit evidence that contains no private key bytes, PINs, or session secrets.
