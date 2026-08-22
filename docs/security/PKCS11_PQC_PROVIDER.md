# PKCS #11 v3.2 PQC Provider

## Status

OmniGuard v3.0.3 contains an **opt-in PKCS #11 v3.2 runtime adapter** for ML-DSA-44 and ML-KEM-512.

This source implementation is not, by itself, evidence that a deployment is hardware-backed. The runtime only exposes hardware-backed/non-exportable capability state after the configured token passes the live checks described below. Release CI does not contain a real PKCS #11 v3.2 PQC hardware token, so CI must not be represented as hardware validation.

TPM2 and generic `hsm` provider names remain unavailable/fail-closed until separate concrete adapters exist.

## Standards basis

The adapter targets OASIS PKCS #11 Specification Version 3.2 and requires the standardized v3.2 `PKCS 11` interface.

Required mechanisms and operations:

- `CKM_ML_DSA_KEY_PAIR_GEN`
- `CKM_ML_DSA` with signing support
- `CKM_ML_KEM_KEY_PAIR_GEN`
- `CKM_ML_KEM` with encapsulation and decapsulation support
- `CKM_SHA3_256` with digest support
- `C_EncapsulateKey`
- `C_DecapsulateKey`
- `C_DigestKey`

The ML-KEM V2 commitment is computed as SHA3-256 over the commitment prefix followed by the raw derived shared-secret object. The shared secret stays inside the PKCS #11 token/session object boundary.

## Build

The provider is disabled by default.

```bash
cmake -S . -B build \
  -DSMARTCAR_FETCH_PINNED_LIBOQS=ON \
  -DSMARTCAR_ENABLE_PKCS11_PROVIDER=ON
cmake --build build --target smartcar_blockchain
```

The build requires a PKCS #11 v3.2 development header named `pkcs11.h` that includes the standardized ML-DSA and ML-KEM definitions. An older PKCS #11 2.x/3.0 header is intentionally rejected by compilation.

Enabling the provider in the build does not make it the active runtime provider. Runtime selection is separate and explicit.

## Runtime configuration

Required provider selection:

```text
SMARTCAR_CPP_PQC_PROVIDER=pkcs11
SMARTCAR_CPP_PQC_HARDWARE_REQUIRED=1
SMARTCAR_CPP_PKCS11_MODULE=/absolute/path/to/vendor-pkcs11-module
```

Select a token using either:

```text
SMARTCAR_CPP_PKCS11_SLOT_ID=<numeric slot id>
```

or:

```text
SMARTCAR_CPP_PKCS11_TOKEN_LABEL=<exact token label>
```

If exactly one token-present slot exists, the slot can be selected without either variable. When both slot ID and token label are supplied, the label must match the selected slot.

Authentication uses exactly one of:

```text
SMARTCAR_CPP_PKCS11_PIN=<token user PIN>
```

or:

```text
SMARTCAR_CPP_PKCS11_PIN_FILE=/path/to/restricted-pin-file
```

`SMARTCAR_CPP_PKCS11_PIN_FILE` must be a regular non-symlink file. If the token advertises a protected authentication path, both PIN inputs may be omitted and the provider passes a null PIN to `C_Login`.

Do not place real PIN values in tracked `.env` files, command examples, CI logs, issue bodies, or release evidence.

## Activation sequence

Hardware activation is intentionally two-phase.

### 1. Backend preflight

Before identity-specific keys are loaded or created, the provider must prove:

- the configured module loads from its canonical path;
- `C_GetInterface` returns the standard PKCS #11 v3.2 interface;
- a token-present slot is selected;
- the slot advertises `CKF_HW_SLOT`;
- a read/write serial session can be opened;
- user login succeeds or is already active;
- ML-DSA-44 key generation/signing mechanisms exist;
- ML-KEM-512 key generation/encapsulation/decapsulation mechanisms exist;
- SHA3-256 digest and `C_DigestKey` are available.

A software PKCS #11 token that does not advertise `CKF_HW_SLOT` cannot satisfy the OmniGuard hardware-backed capability gate.

### 2. Identity key evidence

The provider loads the highest OmniGuard generation for the requested identity. If none exists, generation 1 is generated inside the token.

Private keys are requested with:

- `CKA_SENSITIVE=CK_TRUE`
- `CKA_EXTRACTABLE=CK_FALSE`

After loading/generation, the provider requires the private objects to report:

- `CKA_SENSITIVE=CK_TRUE`
- `CKA_EXTRACTABLE=CK_FALSE`
- `CKA_ALWAYS_SENSITIVE=CK_TRUE`
- `CKA_NEVER_EXTRACTABLE=CK_TRUE`

No private `CKA_VALUE` is read by the adapter.

### 3. Operational key-pair proof

Before active state is exposed:

- ML-DSA signs a provider challenge using the private key and verifies it with the paired public key on the token;
- ML-KEM encapsulates to a non-exportable session secret, decapsulates to a second non-exportable session secret, digests both with SHA3-256 using `C_DigestKey`, and requires the digests to match;
- both proof secret objects are destroyed after the proof.

Only after these checks does the active runtime state set hardware-backed, non-exportable, and runtime-probe-verified to true.

## ML-KEM V2 commitment

For a normal ledger operation the adapter:

1. calls `C_DecapsulateKey` with the active ML-KEM private key;
2. creates the derived secret as a session object with `CKA_SENSITIVE=CK_TRUE` and `CKA_EXTRACTABLE=CK_FALSE`;
3. verifies those attributes;
4. calls `C_DigestInit(CKM_SHA3_256)`;
5. feeds the commitment prefix using `C_DigestUpdate`;
6. feeds the secret object using `C_DigestKey`;
7. completes the digest with `C_DigestFinal`;
8. destroys the derived secret object;
9. returns only the versioned V2 commitment digest.

The adapter does not implement the legacy raw shared-secret export hook. Hardware-backed runtime blocks therefore use the V2 commitment path.

## Generation and rotation behavior

Key labels contain a deterministic identity tag and monotonically increasing generation number. The provider discovers the highest ML-DSA public generation for the identity and requires the corresponding ML-DSA private, ML-KEM public, and ML-KEM private objects to exist.

If the newest discovered generation is incomplete, activation fails closed. It does not silently fall back to an older generation.

Rotation creates generation `N+1`. Older hardware generations are retained. Rotation is intended to be single-writer/operator-controlled; concurrent rotation against one token is not currently a supported workflow.

## Validation claims

The following claims are appropriate after normal CI passes:

- PKCS #11 provider source is present and opt-in;
- default software-provider behavior remains available when policy permits it;
- unavailable hardware providers fail closed;
- static regression tests enforce v3.2, `CKF_HW_SLOT`, non-exportable-key, V2 commitment, and monotonic-generation invariants;
- the standard v3.0.3 software/native Security Baseline remains green.

The following claims require a separate real-hardware evidence run and must **not** be made from normal CI alone:

- a specific HSM/token was successfully loaded;
- ML-DSA-44 keys were generated as non-exportable hardware objects;
- ML-KEM-512 decapsulation occurred in hardware;
- the V2 commitment was produced from a non-exportable hardware-derived secret;
- hardware key rotation was validated on the target device.

## Real-hardware validation evidence

A future device-specific evidence run should record only non-secret metadata:

- provider build commit;
- vendor/module version;
- token manufacturer/model and non-secret serial/device identity;
- selected slot ID;
- PKCS #11 interface version;
- mechanism support results;
- active generation and public key ID;
- pass/fail of ML-DSA pair proof;
- pass/fail of ML-KEM non-exportable commitment proof;
- pass/fail of guarded rotation and restart persistence;
- final Security Baseline commit/run IDs.

Never record the token PIN, private key bytes, ML-KEM raw shared secrets, or session-object values.
