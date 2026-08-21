# Phase 1 — DID One-Time Signature Hardening

This increment closes the Lamport one-time-signature key-reuse weakness in the research DID component.

## Security changes

- Lamport signing keys are explicitly marked as one-time-use material.
- A DID identity can sign only one challenge with a Lamport private key.
- Signing is protected by a lock so concurrent callers cannot reuse the same key.
- Retained private-key references are cleared immediately after the first signature is produced.
- A second signature attempt fails closed with an explicit exhausted-key error.
- DID documents declare `oneTimeUse: true` for the Lamport verification method.
- Proofs identify the exact verification method and explicitly declare one-time-key semantics.
- Verification validates proof/document types, method binding, key type, signature shape, secret length, challenge hash, and every Lamport hash pair.
- Malformed hexadecimal signatures fail closed instead of propagating unsafe partial verification.
- Digest comparison uses constant-time comparison where applicable.
- `successor()` generates a fresh keypair and therefore a fresh DID for the same vehicle controller.

## Operational requirement

Lamport signatures remain suitable only for constrained research use. Every successful Lamport signature permanently exhausts that DID signing key. Applications must publish and trust the successor DID document before using the next key.

For longer-lived operational vehicle identity, Phase 1 should move the active signing path to a standardized post-quantum signature scheme such as ML-DSA, with key enrollment, rotation, revocation, and hardware-backed private-key storage.

## Regression coverage

`tests/test_did_one_time_security.py` verifies:

1. the first Lamport signature validates;
2. a second signature is rejected;
3. retained private material is cleared;
4. a changed challenge fails verification;
5. a tampered signature fails verification;
6. malformed signature encoding fails closed;
7. proof one-time semantics are mandatory;
8. a successor identity receives fresh signing material and a fresh DID.

Focused isolated validation completed successfully: **8/8 tests passed** before publication.
