# Security Hardening v3.1 — Native Build and PQC Policy

## Scope

v3.1 hardens the native C++ build boundary. The goal is to prevent a standard build from silently producing a binary that uses the historical deterministic simulated-PQC path when liboqs is unavailable, and to remove aggressive host-specific compiler behavior from the default security-validation build.

This is research hardening. It is not a claim of production cryptographic certification, formal verification, vehicle-safety certification, or completed hardware-backed key storage.

## Fail-closed PQC build policy

`blockchain.cpp` still contains a deterministic simulated Dilithium/Kyber development path for controlled demonstrations. That source path is not a post-quantum security mechanism.

The CMake policy now behaves as follows:

- `liboqs` available with a supported target: native blockchain build is allowed and links the real library.
- `liboqs` unavailable: configuration fails by default before the blockchain executable is created.
- `SMARTCAR_ALLOW_SIMULATED_PQC_BUILD=ON`: explicit lab-only escape hatch that permits the historical simulation path and emits a warning.
- `SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS=ON`: deterministic CI-only switch used to prove the fail-closed branch even on a host that might have liboqs installed.

Direct ad-hoc compilation of `blockchain.cpp` outside the supported CMake policy can bypass this build gate. Such binaries are outside the hardened build profile and must not be described as post-quantum secure.

## Reproducible/safe Release defaults

The previous Release profile enabled aggressive settings by default. v3.1 changes the default posture:

- Release optimization uses `-O2` on non-MSVC toolchains.
- `-march=native` is disabled by default and requires `SMARTCAR_ENABLE_NATIVE_OPT=ON`.
- `-ffast-math` is disabled by default and requires `SMARTCAR_ENABLE_UNSAFE_FAST_MATH=ON`.
- IPO/LTO is disabled by default and remains available via `SMARTCAR_ENABLE_IPO=ON`.
- opt-in warnings make it explicit when host-specific or relaxed floating-point semantics are requested.

These settings improve portability and reduce accidental differences between validation machines. They do not guarantee bit-for-bit reproducible binaries across compilers, linkers, operating systems, or dependency toolchains.

## Dependency integrity

The nlohmann/json fallback dependency remains pinned to v3.11.3 and now includes the release-published SHA-256 for `json.tar.xz`:

`d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d`

CMake verifies the archive digest before using the fetched source. This reduces dependency-substitution risk for that FetchContent path. It does not replace a complete software supply-chain program, signed provenance, SBOM verification, or hermetic builds.

## CI validation

Security Baseline now includes:

1. static regression checks for safe CMake defaults, checksum pinning, explicit simulation opt-in, and fail-closed behavior;
2. a forced-no-liboqs CMake configure that must fail with the expected policy message;
3. a separate explicit lab-only simulated-PQC configure/build that must succeed;
4. all existing Python security suites, deterministic adversarial/HIL/incident-response scenarios, Go tests, Go fuzz campaigns, and Go build.

## Remaining native-security work

Future phases should consider:

- removing the simulated PQC implementation from the security executable entirely and moving it to a separately named demo target;
- integrating a pinned/verified liboqs build in CI so the real PQC C++ path is compiled and exercised;
- sanitizer and static-analysis jobs for the native C++ targets;
- SBOM/provenance generation and dependency policy enforcement;
- compiler/toolchain pinning for stronger reproducibility;
- review of the legacy XOR-based stream cipher in the C++ demo and migration to an authenticated encryption construction before any non-demo use.
