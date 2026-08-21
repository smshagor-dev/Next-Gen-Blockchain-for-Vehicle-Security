# v2.3 — Ledger Integrity Hardening

This increment extends the previous zero-trust transport and control-API work into the ledger trust boundary.

## Why this change was required

The legacy Python `block_hash` intentionally covers the block index, timestamp, vehicle ID, telemetry SHA3, event SHA3, and previous hash. Several security-relevant fields are populated after that hash is computed, including ZKP evidence, anomaly metadata, smart-contract receipts, edge summaries, forensic blackbox metadata, FL payloads, and Proof-of-Proximity metadata.

The legacy `block_signature` was also generated as an HMAC over only `block_hash` and was not verified by `Block.verify()`.

Changing the historical `block_hash` format in place would invalidate existing checkpoints, PoA signatures, privacy-proof contexts, archive anchors, and compatibility tooling. v2.3 therefore adds a versioned secondary integrity layer instead of silently redefining the legacy chain hash.

## Python ledger integrity seal

`SMARTCAR_LEDGER_SEAL_V2` uses the existing persisted `block_signature` field as a canonical full-block HMAC-SHA256 seal.

The canonical payload includes every serialized block field except `block_signature` itself. This means the seal covers, among other fields:

- event and telemetry data plus their stored hashes,
- PoA / PoP metadata,
- ZKP proofs,
- anomaly metadata,
- smart-contract receipts,
- edge summaries,
- forensic blackbox metadata,
- biometric/safe-mode metadata,
- FL update metadata,
- archive references,
- validity and emergency flags.

The integrity guard is installed by `PythonBackend` and patches that blockchain instance's append, genesis-reset, and chain-verification boundary. Existing committed blocks are verified before an append is allowed. Newly finalized blocks are sealed only after their metadata has been generated.

## Genesis and validator verification

v2.3 explicitly validates block 0 instead of relying on the historical `verify_chain()` loop that starts at index 1.

For every block, including genesis, archived blocks, and `POA_POP` mode blocks, the guard verifies:

- contiguous block index,
- vehicle identity binding,
- previous-hash linkage,
- expected validator identity,
- authority round,
- PoA HMAC signature using the configured authority registry,
- full metadata integrity seal.

This closes the gap where `POA_POP` blocks could bypass the PoA-signature branch inside the legacy `Block.verify()` implementation.

## Archive compaction

Archive compaction intentionally changes an old block's in-memory representation. v2.3 permits a seal rotation only when a block transitions from active to `archived_pruned`, has a matching archive shard/root reference, and its signed shard anchor verifies. Any other retroactive mutation fails closed.

## Go backend verification

The Go backend remains compatible with its current block schema. The Python authenticated client independently recomputes for every Go block:

- telemetry SHA2 and SHA3,
- event SHA2 and SHA3,
- main block hash,
- dual hash,
- index and previous-hash linkage,
- vehicle identity.

It also records a SHA3 fingerprint of the complete block object returned by the authenticated Go process. Within one authenticated service generation, any retroactive change to a previously observed block — including smart-contract receipt edits that are outside the legacy Go block hash — is rejected.

State-enhancing operations such as authentication, engine start, recovery unlock, telemetry append, and save require a valid local ledger audit plus a successful server `/verify` check first. Fail-safe controls such as stop, lock, and emergency brake remain callable even when a ledger warning exists.

## Validation scope

Regression coverage includes:

- receipt tampering against the full metadata seal,
- event tampering against the full metadata seal,
- Go event/hash mismatch rejection,
- Go retroactive receipt edit rejection,
- Go chain-length regression rejection,
- Python genesis verification,
- Python post-commit metadata tamper rejection,
- append refusal after detected tampering.

The existing sync, DID/Lamport, V2X, control-API, Go tests, and Go build remain in the Security Baseline workflow.

## Security boundary and limitations

This hardening is defense-in-depth, not a claim of an unhackable or safety-certified vehicle platform.

The Python seal is persistent because it reuses the serialized `block_signature` field. The Go protection currently provides independent hash validation and authenticated-process-generation immutability at the Python client boundary; it does **not** yet add a new persisted server-side signature over the complete Go block metadata. A future Go ledger-format revision can add that without changing the legacy block hash.

Compromise of the host account with access to live process memory and all secrets is outside the protection boundary of an HMAC-only software implementation. Hardware-backed keys, OS privilege separation, and TPM/HSM-backed sealing remain future hardening work.
