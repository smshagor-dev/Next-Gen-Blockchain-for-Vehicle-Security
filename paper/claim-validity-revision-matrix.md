# Revision evidence matrix (working checklist)

The editor decision email of 2026-11-24 confirms major revision, due
2026-12-08, and requests accurate reporting, bounded conclusions,
limitations, a point-by-point response, matching Data Availability text
in the manuscript and submission system, and code deposit in a
DOI-assigning repository. Exact reviewer reports are not included in that
email. Reviewer-specific items below are working paraphrases from prior
discussion, not verbatim comments or a final response. Reopen the original
portal reports and manuscript before numbering and quoting them.

| Concern | Evidence / revision action | Status |
|---|---|---|
| R4: analytical 7/8 mismatch follows design | Preserve 576 cases and 87.5% as constructive enumeration only; add actual component pilots separately (consensus, identity, PQC observed documents). | Evidence available; manuscript rewrite pending |
| R4: practical interpretation and supported claims | Discuss local assurance consumer scenario and possible overinterpretation of STRONG; no human study or actual user misuse observed. Use narrow negotiated mode, enrolled session and recorded quorum claims. | Evidence available; wording pending |
| R4: rationale for assumptions, hybrid/fallback | Actual liboqs-backed handshake, ECDH and PSK alternatives; controlled sync admissions and validator quorum tests. Cite FIPS 203 and RFC 9794. | Evidence available; terminology correction pending |
| R4/R7: synthetic evidence and single version | 240 local component trials and 82 new fixed-design fresh-subprocess trials. These remain controlled tests of one prototype, with constructed health wrappers, not live dashboard capture, network/HIL or multiple versions. | Partially addressed, limits remain |
| R4: gate/oracle circularity | Separate design reference and outcome checks; matched proxy comparison, evidence faults and ablation, observer trust failure. Same-process trust remains and predicates are constructive; no externally trusted adjudication. | Partially addressed |
| R4: exact scripts and timing | Frozen candidate, schedule and execution SHA; local microbenchmark excludes transport, acquisition and cryptographic cost. Retain all raw timings and explicitly reconcile prior S3 outlier/exclusion rationale in manuscript. | Evidence available; old outlier review pending |
| R5: feedback | Verify original report; preserve supported revisions without inventing new requests. | Original report needed |
| R6: equation and eight STRONG cases | State analytical conjunction and operational-plus-claim eligibility separately; 7 downgraded and all-assumptions case preserved in the constructed design, not proof. | Manuscript edit pending |
| R6: author affiliation, funding, COI, figure captions | Confirm author metadata and declarations; explain line styles in original Fig. 1–2. | Manuscript edit pending |
| R7: established novelty, weak flags and missing real traces | Related-work boundary includes closest 2026 cryptographic assurance work, actual local component evidence and separate reference; no invented field data or claim of first. | Partial; full-text comparator and cross-version evidence remain open |
| R7: references 16/19/20/21, Table 3/Fig. 5, 5.34 ms exclusion | Reopen exact manuscript, cite or remove orphaned references, correct labels/denominators and document exclusions transparently. | Pending exact manuscript check |
| Editor: DOI code deposit | Archive exact executable revision, dependencies, raw traces, generated tables/figures, hashes and reproduction instructions in Zenodo. | Pending DOI |
| Editor: identical Data Availability | Write one evidence-specific statement after archive DOI is assigned; copy unchanged into portal and manuscript. | Pending |
| Editor: point-by-point response | Use verbatim original reports with response and exact page/line evidence; avoid calling partially resolved issues closed. | Pending original reports and final manuscript |

## Evidence anchors

- Pilot reports: claim-validity-consensus-pilot-observed.md,
  claim-validity-identity-pilot-observed.md, claim-validity-pqc-pilot-observed.md.
- Held-out: claim-validity-heldout-observed.md and claim-validity-heldout-protocol.md.
- Audited artifacts: claim-validity-publication-audit-observed.md.
- Literature: claim-validity-related-work.md.

Do not include private submission portal links or personal correspondence
in the public reproducibility archive. This checklist is an internal
revision aid; exclude it from a public release unless author approves.
