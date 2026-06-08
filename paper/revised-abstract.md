# Revised Abstract

OmniGuard V2X is a hybrid-security prototype framework for smart vehicle systems that integrates vehicle sensing, identity/authentication metadata, privacy commitments, blockchain audit logging, federated-learning validation hooks, and dashboard/API security reporting. The prototype is intentionally framed as an engineering integration and validation-transparency system, not as a fully new cryptographic construction or an end-to-end post-quantum security result.

Post-quantum protection is limited to the ML-KEM/Kyber key-establishment path. The Pedersen commitment and Schnorr-style proof components remain classical-assumption mechanisms, including discrete-log-based binding and proof soundness. Lamport-based DID metadata provides identity authenticity for enrolled identities, but it does not provide Sybil resistance under open registration. The simple-majority audit chain provides tamper-evident logging under its stated assumptions, but it does not resist majority control of validators.

The federated-learning and adversarial-detection modules are retained as prototype validation components and experiment hooks. Prior tiny single-run checks are treated as sanity checks only, not as evidence for general Byzantine robustness or general attack-detection performance. Larger experiments with realistic datasets, repeated seeds, stronger adversaries, false-positive/false-negative analysis, confidence intervals, and runtime scalability measurements are required before strong general claims can be made.

