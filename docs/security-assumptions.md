# OmniGuard V2X Security Assumptions

The current prototype provides hybrid security, not end-to-end post-quantum
security. Post-quantum protection is limited to the ML-KEM/Kyber key
establishment path unless the classical commitment/proof components are
replaced.

| Component | Security property | Assumption | PQ-safe? | Limitation |
| --- | --- | --- | --- | --- |
| ML-KEM-512 / Kyber512 | Key establishment | Module-LWE | Yes | Requires real liboqs/ML-KEM support; simulated mode is not a cryptographic PQ implementation. |
| Dilithium / ML-DSA path | Authentication/signature | Lattice assumptions | Yes, when real liboqs implementation is active | Simulated fallback is for development only. |
| Pedersen Commitment | Hiding | Information-theoretic hiding with fresh blinding | Yes | Implementation still depends on correct randomness and parameter handling. |
| Pedersen Commitment | Binding | Discrete Log / DDH in MODP group | No | Quantum adversaries can attack the discrete-log binding assumption. |
| Schnorr-style Knowledge Proof | Soundness | Discrete Log | No | Educational proof construction, not a PQ-safe range proof. |
| Speed relation/range proof | Soundness | Schnorr/classical discrete-log assumption | No | Does not provide post-quantum soundness; replace with a real PQ-safe proof system for full PQ claims. |
| ECDH-P256 fallback | Key exchange fallback | ECDLP | No | Disabled by default; enabling it is explicit opt-in and must be treated as classical. |
| SHA2/SHA3 dual hashing | Integrity hashing | Hash preimage/collision resistance | Partially | Grover's algorithm affects symmetric security margins; hashing alone does not make classical protocols PQ-safe. |

Security modes used in code:

- `PQ_HYBRID_AUTHENTICATION`
- `CLASSICAL_PRIVACY_COMMITMENT`
- `LEGACY_ECDH_FALLBACK_DISABLED_BY_DEFAULT`

Accurate system claim:

> OmniGuard V2X uses ML-KEM/Kyber for post-quantum key establishment, while
> its Pedersen commitment binding and Schnorr-style proof soundness rely on
> classical discrete-log assumptions. The current prototype provides hybrid
> security, not end-to-end post-quantum security.
