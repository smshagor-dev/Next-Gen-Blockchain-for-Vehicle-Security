# Reviewer Response Summary

The project has been revised to remove overstated or unsupported claims and to expose security boundaries through documentation, API metadata, dashboard cards, and reproducible experiment scaffolding. The corrected status is bounded prototype readiness, not accepted-ready publication status.

| Reviewer issue | Correction summary |
| --- | --- |
| Overstated post-quantum security | Reframed as hybrid security. ML-KEM/Kyber is limited to key establishment; classical components remain explicitly labeled. |
| Invalid Sybil-resistance theorem | Reframed Lamport DID as identity authenticity only. Open registration is documented as not Sybil resistant. |
| Incorrect 51% attack theorem | Removed majority-attack-resistance claim for simple-majority consensus and documented majority-control limits. |
| Weak FL evaluation | Reframed tiny FL result as a prototype sanity check and added CSV-backed future evaluation tooling. |
| Perfect detection / trivial attack tests | Reframed detection as single-run attack-trigger validation and added CSV-backed adversarial metrics tooling. |
| Inconsistent layer count | Standardized the system as six implemented prototype layers. |
| Inconsistent latency numbers | Standardized the active latency statement to 5.34 ms warm-start prototype pipeline latency and added metrics source-of-truth documentation. |
| Unclear novelty | Added contribution-boundary framing: no new cryptographic primitives; contribution is integration and validation transparency. |
| O(n) vs O(n^2) mismatch | Added component-level complexity analysis and documented naive full-mesh/all-validator communication limits. |
| Pedersen aggregate-statistics claim | Corrected Pedersen wording: homomorphic combination is supported, but aggregate statistics are not recoverable without openings or a future secure aggregation protocol. |

