# Contributions

OmniGuard V2X does not introduce a new cryptographic primitive. Its contribution is system integration plus validation transparency for a cross-layer smart-vehicle security prototype.

## Project Contributions

- Cross-layer prototype integration across C++, Python, Go/API, and dashboard components.
- Runtime security capability reporting that exposes active security modes and disabled claims.
- Assumption-aware dashboard/API metadata for post-quantum boundaries, identity limits, consensus limits, privacy modes, FL validation level, adversarial validation level, complexity, and reviewer audit state.
- Reviewer-audit metadata that records invalid or unsupported claims as disabled.
- Reproducible experiment framework for latency microbenchmarks, communication-volume scalability analysis, CSV-backed adversarial evaluation, CSV-backed FL evaluation, and final report aggregation.

## Reused Components

- ML-KEM/Kyber key-establishment path.
- Pedersen commitments and classical proof concepts.
- Lamport one-time-signature identity authenticity.
- SHA2/SHA3 hashing.
- mTLS/API security patterns.
- Simple-majority blockchain audit logic.
- Robust-aggregation and FL poisoning-detection concepts.

## Not Claimed

- New post-quantum cryptographic primitive.
- End-to-end post-quantum security for every layer.
- Sybil resistance under open registration.
- Majority-control or 51% attack resistance under simple-majority consensus.
- Secure aggregate-statistics recovery from commit-only Pedersen commitments.
- Statistically proven FL robustness.
- General perfect attack detection.

