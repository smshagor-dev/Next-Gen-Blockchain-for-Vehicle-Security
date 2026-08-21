# v3.2 Native C++ Crypto Modernization

## Scope

This phase hardens the supported native C++ blockchain build after v3.1 made
missing-liboqs builds fail closed. The goal is to remove legacy cryptographic
fallbacks from the production executable rather than merely hiding them behind
runtime labels.

This is research hardening. It is not production cryptographic certification,
formal verification, penetration-test certification, or vehicle-safety
certification.

## Threats addressed

The historical `blockchain.cpp` contained two compatibility mechanisms that are
not appropriate for the supported security target:

- XOR plus Base64 for persisted `dual_hash` data, which provides no modern
  authenticated-encryption guarantee.
- A deterministic simulated-PQC fallback that could generate artifacts without
  real ML-KEM/ML-DSA cryptography when liboqs was unavailable.

The historical demo also embedded sample credentials in `main()`.

v3.2 isolates that source from the supported native target and introduces a new
security core with explicit credentials, authenticated encryption, standardized
PQC algorithms, full-chain verification, and executable-level CI validation.

## Build boundary

### Supported target

`smartcar_blockchain` now compiles only:

`native/secure_blockchain.cpp`

The target requires:

- OpenSSL 3 `Crypto`
- real liboqs
- nlohmann/json

There is no simulated-PQC code and no `SimpleEncrypt` XOR helper in this source.
If real liboqs is unavailable, CMake stops before producing the supported binary.

### Legacy compatibility target

Historical `blockchain.cpp` remains in the repository for controlled research
comparison and compatibility work, but it can only be compiled through the
explicitly named target:

`smartcar_blockchain_legacy_demo`

That target is disabled by default and remains outside the hardened production
build profile. It must not be described as a post-quantum-secure or production
vehicle-security executable.

## Native data protection

The secure native core requires an independent environment credential:

`SMARTCAR_CPP_DATA_KEY`

The credential policy treats this as the separate `native_cpp_data` security
domain. Exact reuse with authentication, API, validator, recovery, V2X,
hardware-device, storage, forensic, insurance, or incident-response credentials
is rejected by the shared Python credential policy.

The native source requires at least 32 characters and derives a fixed 256-bit
AES key using SHA-256 with the domain string `OMNIGUARD_CPP_DATA_KEY_V1`.
This input is expected to be a generated high-entropy secret; this derivation is
not represented as a password KDF.

Persisted `dual_hash` values use AES-256-GCM with:

- 96-bit random nonce from `RAND_bytes`
- 128-bit authentication tag
- associated data binding vehicle identity, block index, and block hash
- explicit algorithm/version metadata in the JSON envelope

The self-test proves a valid envelope decrypts and a modified GCM tag is
rejected.

This does not make the entire ledger confidential. Event, telemetry, block,
and PQC metadata remain visible in the persisted research ledger.

## Real PQC path

The secure core uses only standardized identifiers:

- `ML-DSA-44`
- `ML-KEM-512`

For each block it:

1. signs the domain-separated block/PQC message with ML-DSA-44;
2. encapsulates to the process ML-KEM-512 keypair;
3. decapsulates and checks sender/receiver shared-secret equality;
4. immediately hashes the shared secret into a domain-separated digest;
5. wipes temporary shared-secret and private-key buffers on the implemented
   software path;
6. binds signature, KEM ciphertext, shared-secret hash, block hash, dual hash,
   previous hash, and timestamp into the committed PQC metadata.

No simulated signature/KEM artifact is accepted by `smartcar_blockchain`.

## Pinned liboqs source build

The normal build prefers an installed liboqs package. Reproducible CI/source
validation may explicitly enable:

`-DSMARTCAR_FETCH_PINNED_LIBOQS=ON`

The repository pins liboqs 0.16.0 to the full commit:

`5a1a854b0dc9f2141bdc771c555ee60c37950183`

The fetched build is minimized to:

`KEM_ml_kem_512;SIG_ml_dsa_44`

A commit pin improves source reproducibility but is not a complete software
supply-chain attestation mechanism.

## Ledger verification

The secure native verifier checks every block including genesis:

- contiguous index
- vehicle identity
- genesis/linkage previous hash
- telemetry SHA-256 and SHA3-256 recomputation
- event SHA-256 and SHA3-256 recomputation
- block hash recomputation
- dual-hash recomputation
- ML-DSA signature verification
- ML-KEM decapsulation and shared-secret hash validation
- PQC binding/digest validation

Appending or saving refuses to continue if the existing chain fails validation.

## Authentication boundary

The executable requires `SMARTCAR_AUTH_TOKEN`; there is no hardcoded valid token
in the secure source. Authentication compares a domain-separated SHA3-256 digest
using a constant-time byte comparison and requires the chain to validate before
unlocking the local demo state.

This remains a research/demo authentication boundary and is not a substitute for
hardware-backed vehicle identity, production PKI, or ECU authorization.

## CI validation

The Security Baseline now verifies all of the following:

- existing Python security regression suites
- v3.2 source/build-policy regression tests
- hardened target fails closed when liboqs is forced unavailable
- legacy `blockchain.cpp` builds only as the isolated legacy target
- pinned real liboqs source builds the supported native target
- native crypto self-test exercises AES-GCM tamper rejection, authentication,
  ML-DSA/ML-KEM block creation, and full-chain verification
- existing deterministic adversarial, software-HIL, incident-response, Go
  security/fuzz, and Go build gates remain active

## Remaining limitations

- `SMARTCAR_CPP_DATA_KEY` is currently process-provided software key material;
  TPM/HSM/non-exportable native data-key operations remain future work.
- The legacy C++ demo still exists in the repository for controlled comparison.
  It is intentionally not deleted in this phase, but is excluded from the
  supported executable.
- The secure target currently generates ephemeral ML-DSA/ML-KEM keypairs at
  process startup; durable protected PQC identity/key provisioning is future work.
- The persisted ledger format introduced by the secure native target is a new
  research format and does not silently migrate historical legacy C++ files.
- AES-GCM protects the selected encrypted field; it is not a full-ledger
  confidentiality layer.
- A sufficiently privileged local process/OS attacker remains outside this
  software-only trust boundary.
