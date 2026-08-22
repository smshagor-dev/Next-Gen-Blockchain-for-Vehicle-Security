# OmniGuard V2X Changelog

This changelog summarizes the public release sequence for the research hardening line. Internal engineering phase labels are noted where they differ from public patch-version numbering.

## v3.0.3 — Durable PQC Identity, Historical Trust & Runtime Recovery Hardening

Internal hardening phase: `v3.3`.

- Adds a durable encrypted ML-DSA-44 / ML-KEM-512 identity keystore with AES-256-GCM protection for software-stored private material.
- Adds guarded local PQC key rotation, encrypted previous-keystore backups, signed old-to-new transitions, and a bounded historical public-key trust keyring.
- Adds mixed-generation native ledger verification so admitted historical ML-DSA generations remain verifiable while new active-generation blocks can be appended safely.
- Explicitly reports that historical ML-KEM private keys are not retained and historical shared-secret claims are not independently re-decapsulated.
- Adds the authenticated `OMNIGUARD_PQC_ROLLBACK_ANCHOR_V1` software rollback/recovery state boundary with explicit no-auto-restore behavior and no claim of hardware monotonicity.
- Adds an opt-in PKCS#11 v3.2 hardware PQC adapter for ML-DSA-44 / ML-KEM-512, gated by real token/mechanism/non-exportability runtime evidence; TPM2 and generic HSM adapters remain unavailable and fail closed.
- Adds PKCS#11 v3.2 source/ABI conformance validation using canonical OASIS headers and strict C++ compilation.
- Adds secure local `.env` bootstrap with independent high-entropy credentials, preserved existing secrets by default, explicit full rotation, and no secret-value printing.
- Hardens authenticated Go loopback startup with stale-endpoint detection, bounded 45-second cold-start readiness, dedicated backend logs, and child-only cleanup.
- Development runtime selection now prefers checked-out Go source when the Go toolchain is present, avoiding silent reuse of stale local prebuilt `smartcar_go_backend.exe` artifacts; packaged/no-Go environments can still use compatible prebuilt binaries.
- Adds regression coverage for local credential bootstrap, stale loopback authentication mismatch, startup timeout bounds, and source/prebuilt runtime selection.
- Adds commit-bound release integrity manifests, deterministic SBOM generation, build provenance, current-tree secret scanning, SHA-256 publication checksums, and guarded exact-main tag/publication workflows.
- Keeps release claims bounded: research validation only, no production automotive certification, formal verification, production HSM custody claim, or hardware-monotonic rollback guarantee.

## v3.0.2 — Native Cryptographic Modernization & Real-PQC Validation

Internal hardening phase: `v3.2`.

- Supported native C++ target uses AES-256-GCM authenticated encryption for protected persisted data.
- Supported native target uses real liboqs ML-DSA-44 signatures and ML-KEM-512 key encapsulation.
- Historical XOR and simulated-PQC code is excluded from the supported native executable and isolated to an explicit legacy/lab target.
- Pinned liboqs 0.16.0 source path is compiled in hosted CI.
- Native self-test verifies AEAD tamper rejection, authentication gating, ML-DSA signing, ML-KEM binding, telemetry append, and full-chain verification.
- Adds canonical public version identity (`VERSION`, CMake, Python/Go release metadata) and CI drift protection.

## v3.0.1 — Native Build & PQC Enforcement

Internal hardening phase: `v3.1`.

- Native blockchain configuration fails closed when real liboqs is unavailable.
- Simulated PQC is available only through an explicit lab/demo compatibility target.
- Release defaults use `-O2`; `-march=native`, `-ffast-math`, and IPO/LTO are opt-in.
- nlohmann/json fallback archive is checksum pinned.
- Native build-policy regression tests and fail-closed CMake CI gates were added.

## v3.0.0 — Authenticated Hardware Bridge & Bench Safety

- Added per-device hardware transport credentials and authenticated envelopes.
- Added timestamp/nonce replay protection, identity binding, message-direction binding, and strict telemetry validation.
- Plain TCP hardware transport defaults to loopback; private-LAN testing requires explicit lab policy.
- Physical actuation is disabled by default and protected by an explicit bench-only interlock gate.
- The interlock is an operational research guardrail, not a certified vehicle safety mechanism.

## v2.9.0 — Incident Response & Recovery Gates

- Added latched incident lifecycle handling and tamper-evident evidence journaling.
- Added separate evidence-authentication and operator-authorization credential domains.
- Added signed operator actions with timestamp/nonce replay protection.
- Recovery requires explicit acknowledgement, a healthy observation window, no new containment evidence, and safety-interlock confirmation for critical incidents.
- Persisted journal tampering blocks recovery transitions.

## v2.8.0 — Runtime Detection & Software-HIL Validation

- Added bounded cross-layer runtime security correlation with NORMAL/WATCH/CONTAIN/CRITICAL states.
- Added value-minimized, SHA3-linked evidence records without raw credentials or packet bodies.
- Added network-isolation and safe-mode request decisions without direct monitor-driven physical actuation.
- Added deterministic software-HIL scenarios for replay, cross-layer auth/consensus attacks, ledger tamper, service spoof indications, and telemetry-integrity failures.

## v2.7.0 — Adversarial Validation & Bounded Fuzzing

- Added deterministic repo-local adversarial campaigns for sync, consensus, ledger, and control API boundaries.
- Added malformed/corrupted security corpora.
- Added bounded replay caches that fail closed under nonce saturation.
- Added native Go fuzz targets for path confinement, malformed emergency payloads, unsigned protected mutations, and health challenge parsing.
- Hosted adversarial validation completed with zero unexpected campaign failures in the recorded release run.

## v2.6.0 — Permissioned Consensus & Identity Admission

- Added fixed permissioned validator membership and signed epoch-scoped votes.
- Bound signatures to proposal ID/hash, validator identity, vote value, epoch, and proposal timestamp.
- Added duplicate/equivocation rejection, stale proposal rejection, finalization protection, and full-validator-set quorum calculation.
- Normal network admission moved toward explicitly enrolled identities; global-PSK admission is lab-only compatibility.
- Permissioned membership reduces outsider/Sybil voting risk but does not prevent capture by a sufficiently large malicious authorized coalition.

## v2.5.0 — Key Provider Boundary & Runtime Isolation

- Added key-provider abstraction and value-free key-access auditing.
- Added best-effort mutable secret-buffer zeroization.
- Hardware-provider selection fails closed when no real adapter exists; software fallback can be forbidden explicitly.
- Hardened Python-to-Go process spawning with deny-by-default SMARTCAR environment inheritance, injection-variable stripping, descriptor closure, and detached process/session behavior where supported.
- Added Go runtime environment sanitization and Unix hardening controls.

## v2.4.0 — Credential & Key Policy Hardening

- Added centralized fail-closed credential policy.
- Added minimum-length, placeholder, and cross-domain secret-reuse rejection.
- Added PoA, sync, and V2X registry validation.
- Added current/previous secret rotation slots without automatically trusting previous credentials.
- Missing sensitive configuration no longer silently activates embedded/reused defaults in normal strict mode.

## v2.3.0 — Full Ledger Integrity & Tamper Detection

- Added versioned full-block integrity sealing beyond the historical block hash.
- Explicitly verifies genesis, validator identity, authority round, PoA signature, full metadata seal, and archive-transition evidence.
- Rejects append when prior committed state is tampered.
- Added independent Go-side snapshot verification, retroactive-mutation detection, and chain-regression rejection.
- Sensitive Go operations require local audit plus server chain verification.

## v2.2.0 — Authenticated Go Control API

- Added independent control API secret and authenticated health challenge-response.
- Added HMAC request signing over method/path/timestamp/nonce/body hash.
- Added replay/staleness rejection, strict methods/JSON/body limits, loopback-only transport, and one-time non-reconfigurable initialization.
- Added path-confined persistence, restricted temporary-file writes, dedicated recovery credential, and fail-closed Python fallback policy.
- Added Go security regression tests and real-process authenticated smoke validation.

## v2.1.0 — Zero-Trust Sync, DID & V2X Hardening

- Added authenticated sync handshake, mandatory session MACs, replay protection, and vehicle/session identity binding.
- Added per-vehicle credentials and authenticated-validator vote binding.
- Invalid synchronized chains no longer overwrite local/server state.
- Hardened Lamport one-time DID key lifecycle and successor identities.
- Hardened V2X node enrollment, authenticated forwarding, sender/session binding, replay protection, and deterministic fallback behavior.

## v2.0.1 — Security Baseline & Repository Hygiene

- Removed tracked runtime secret configuration from the active tree and added sanitized examples.
- Hardened environment parsing, including literal `#` handling and required-secret checks.
- Expanded repository ignore rules for local credentials, caches, logs, builds, and development artifacts.
- Added initial security regression coverage and operational guidance for rotating historically exposed credentials.

## Security Scope

OmniGuard V2X remains a research and validation framework. These releases improve fail-closed behavior, authentication, integrity, isolation, adversarial testing, and cryptographic implementation quality, but they do not constitute production automotive certification, ISO 26262/ASIL certification, formal verification, or a guarantee against all cyberattacks.
