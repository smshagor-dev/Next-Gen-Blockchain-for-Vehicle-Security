# Contribution Boundary

OmniGuard V2X does not introduce new cryptographic primitives. Its contribution is a prototype system architecture that integrates post-quantum key-establishment metadata, classical privacy mechanisms with explicit assumption labels, identity/authentication, blockchain audit logging, FL sanity checks, and GUI/API security-boundary reporting.

## Novel / Project Contribution

- Cross-layer prototype integration.
- Runtime security capability reporting.
- Explicit assumption/limitation metadata.
- Reproducible validation-plan scaffolding.
- Unified C++/Go/Python demonstration stack.

## Reused Standard Components

- ML-KEM/Kyber.
- Pedersen commitments.
- Lamport OTS/DID.
- SHA2/SHA3 hashing.
- mTLS/API security.
- Majority blockchain logic.
- Robust aggregation concepts.

## Not Claimed

- New PQ cryptographic primitive.
- Full PQ security.
- Sybil resistance under open registration.
- 51% attack resistance.
- Statistically proven FL robustness.
- General 100% attack detection.

## Future Work

- Replace classical commitment/proof components with formally analyzed post-quantum alternatives where appropriate.
- Add production-grade admission control for Sybil resistance.
- Evaluate BFT or stake/certificate-backed consensus instead of simple majority assumptions.
- Run multi-seed adversarial and FL validation protocols with confidence intervals.
- Harden API deployment with real mTLS configuration, key rotation, and audited authorization policy.
