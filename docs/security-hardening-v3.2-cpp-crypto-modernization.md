# v3.2 Native C++ Crypto Modernization

## Scope

v3.2 removes legacy cryptographic fallbacks from the supported native C++ executable rather than merely labeling them as compatibility behavior. This remains research hardening, not production cryptographic certification, formal verification, or vehicle-safety certification.

## Supported native target

`smartcar_blockchain` compiles only `native/secure_blockchain.cpp` and requires OpenSSL 3 Crypto plus real liboqs. The supported source contains neither the historical XOR `SimpleEncrypt` helper nor simulated PQC. If real liboqs is unavailable, CMake fails before producing the supported executable.

Historical `blockchain.cpp` remains available only through the explicitly named, default-off `smartcar_blockchain_legacy_demo` target for controlled compatibility/research comparison. That target is outside the hardened build profile.

## Authenticated data protection

The secure native core requires an independent high-entropy `SMARTCAR_CPP_DATA_KEY`, registered as the separate `native_cpp_data` credential domain. Exact key reuse with other configured security domains is rejected by the shared credential policy.

Persisted `dual_hash` values use AES-256-GCM with a 96-bit random nonce, 128-bit tag, and associated data binding vehicle ID, block index, and block hash. The native self-test verifies normal decryption and rejection after tag tampering. This protects that selected field; it does not make the full ledger confidential.

## Real post-quantum path

The supported target uses only liboqs `ML-DSA-44` and `ML-KEM-512`. Per block it signs a domain-separated block message, performs KEM encapsulation/decapsulation, verifies shared-secret agreement, stores a hash rather than the shared secret, and binds the signature/KEM evidence to the block metadata.

No simulated signature/KEM artifact is accepted or compiled into `smartcar_blockchain`.

## Pinned liboqs validation

Normal builds may use an installed liboqs package. CI/source validation can explicitly enable `-DSMARTCAR_FETCH_PINNED_LIBOQS=ON`, which pins liboqs 0.16.0 to full commit `5a1a854b0dc9f2141bdc771c555ee60c37950183` and limits the fetched algorithm set to `KEM_ml_kem_512;SIG_ml_dsa_44`.

A commit pin improves source reproducibility but is not complete supply-chain attestation.

## Ledger verification

The native verifier checks every block, including genesis: contiguous index, vehicle identity, previous-hash linkage, telemetry SHA-256/SHA3-256, event SHA-256/SHA3-256, block hash, dual hash, ML-DSA signature, ML-KEM decapsulation/shared-secret hash, and PQC binding/digest. Append and save operations refuse to proceed if verification fails.

## CI contract

The Security Baseline must prove all of the following before v3.2 is considered validated:

- existing Python security regression suites pass;
- deterministic adversarial, software-HIL, and incident-response scenarios pass;
- forcing liboqs unavailable makes the hardened CMake target fail closed;
- the historical source builds only through the isolated legacy target;
- pinned real liboqs builds `smartcar_blockchain`;
- the secure native self-test passes AES-GCM tamper rejection, authentication, real ML-DSA/ML-KEM block creation, and full-chain verification;
- existing Go security tests, bounded fuzz campaigns, and Go build remain green.

## Remaining boundaries

- `SMARTCAR_CPP_DATA_KEY` is currently process-provided software key material; TPM/HSM/non-exportable native key operations remain future work.
- ML-DSA/ML-KEM keys are currently generated per process; durable protected PQC identity provisioning is future work.
- The secure native ledger format does not silently migrate historical legacy C++ files.
- The legacy demo remains in the repository for controlled comparison and must not be represented as the supported security executable.
- A sufficiently privileged local OS/process attacker remains outside this software-only trust boundary.
