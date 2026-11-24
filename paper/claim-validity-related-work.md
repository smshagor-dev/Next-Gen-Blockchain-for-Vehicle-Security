# Claim-validity related work and novelty boundary — 2026-11-24

Scope: targeted literature check, not a systematic review. Publisher abstracts,
institutional records and standards summaries were inspected. No published
implementation was reproduced in this study; conceptual comparisons are not
performance comparisons or claims of superiority.

| Source | Established contribution relevant here | Difference and implication for this study |
|---|---|---|
| Campbell, Runtime Cryptographic Evidence to Bounded Assurance Verdicts (2026), Computers 15(10), 659, https://doi.org/10.3390/computers15100659 | Runtime evidence, provenance, registered cryptographic conformance and policy appraisal with bounded verdicts | Closest conceptual overlap. Our limited local observation gate has weaker provenance and no equivalent conformance contract; comparison concerns three V2X component claims, controlled fallback/admission/quorum conditions and coverage. Do not claim first runtime evidence gate or superior assurance. |
| Mohamad et al., CASCADE (2023), ACM TCPS, https://doi.org/10.1145/3569459 | Asset-oriented automotive security assurance case and quality reasoning aligned with ISO/SAE 21434 | This study evaluates narrow runtime claim eligibility instead of constructing a complete automotive security case; no standard compliance claim. |
| Security assurance cases—state of the art of an emerging approach (2021), https://doi.org/10.1007/s10664-021-09971-7 | Established evidence-supported security arguments, including dynamic approaches | Claim/evidence distinction is not novel; the empirical prototype case is the proposed contribution. |
| Increasing the Confidence in Security Assurance Cases using Game Theory (2024), https://doi.org/10.1145/3664476.3664501 | Runtime adaptation of assurance cases and decision strategies | Different decision problem; no game-theoretic optimization or confidence superiority asserted here. |
| Denney, Pai and Habli, Dynamic Safety Cases for Through-Life Safety Assurance (2015), https://doi.org/10.1109/ICSE.2015.199 | Operational updating of safety assurance | Runtime updating is established; our case concerns limited security claims, not dynamic safety certification. |
| Safe autonomous systems in a changing world: Operationalising dynamic safety cases (2025), https://doi.org/10.1016/j.ssci.2025.106965 | Context-sensitive dynamic assurance for autonomous systems | Different assurance scope; this prototype is not a safety assurance framework. |
| ACCESS: Assurance Case Centric Engineering of Safety-critical Systems (2024), https://doi.org/10.1016/j.jss.2024.112034 | Model-based evidence traceability and automated assurance evaluation | No formal assurance-case verification or equivalent engineering tooling here. |
| A Survey of Security and Privacy Issues in V2X Communication Systems (2023), https://doi.org/10.1145/3558052 | V2X authentication, privacy and misbehavior-detection context | Motivates separation between authenticated communication and trustworthy content; our evaluation is not a misbehavior detector. |
| State-of-the-art authentication and verification schemes in VANETs: A survey (2024), https://doi.org/10.1016/j.vehcom.2024.100804 | Authentication, trust and Sybil risks in vehicular networks | Enrollment is not physical uniqueness or general Sybil resistance. |
| Castro and Liskov, Practical Byzantine Fault Tolerance (1999), https://www.usenix.org/conference/osdi-99/practical-byzantine-fault-tolerance | Fault-model-specific replication guarantees | Our threshold tally is not PBFT and quorum acceptance is not validator honesty or external policy validity. |
| IETF RFC 9334 (2023), https://www.rfc-editor.org/rfc/rfc9334.html | Attestation roles, reference values, appraisal policy, integrity and freshness | Local observation timestamps and digests do not supply authenticated remote evidence; explicitly delimit weaker trust boundary. |
| IETF RFC 9794 (2025), https://www.rfc-editor.org/rfc/rfc9794.html | Terminology for traditional/post-quantum combinations | Alternative ML-KEM, ECDH and PSK paths do not establish a composite PQ/traditional key agreement. |
| NIST FIPS 203 (2024), https://doi.org/10.6028/NIST.FIPS.203 | Standardized ML-KEM algorithm | Negotiation observations do not establish complete implementation conformance, certification or end-to-end PQ protection. |

## Defensible candidate contribution

The study contributes a bounded, reproducible software case study of the
relationship between an existing operational classifier and three distinct
claim-specific execution outcomes in one V2X prototype. Deliberate
assumption/configuration interventions expose why posture, declared
capability and observed session/tally state must be distinguished. A local
eligibility prototype is evaluated on matched records, evidence faults,
observer trust failure and newly specified fixed-design cases. The strongest
contribution is the empirical cross-layer comparison and its explicit
abstention/trust limits, not the general idea of an AND gate, runtime evidence,
cryptographic assurance, or claim-based security.

No claim of first-of-kind novelty, new crypto, full PQ protection, Sybil
resistance, Byzantine fault tolerance, production security, vehicle safety,
or statistically generalizable superiority. Existing comparisons are internal
constructed proxies and an ablation, not reproduced state-of-the-art methods.
The literature scan cannot exclude closer prior work. Full text screening of
closest papers, exact manuscript citation reconciliation and a published-method
comparator (or explicit rationale why not comparable) remain open.

## Terminology correction

Use "multi-mechanism prototype with post-quantum and traditional alternatives"
where appropriate. Clarify that an individual selected session mode is not a
simultaneous ML-KEM/ECDH composite key exchange. Use "recorded quorum
acceptance", "enrolled session" and "negotiated ML-KEM-512 session"; distinguish
these from the three broader assumption predicates in the prior analytical
matrix. Do not present them as interchangeable endpoints.
