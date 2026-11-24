# Cross-layer security claim validity — revision execution protocol

Baseline main: 0e3429a8bf6338ff99779dbc7cc4aa61972932ee (v4.0.0; frozen comparison, no rewrite).
Research branch: research/security-claim-validation.

## Scope and reviewer gates

| Revision concern | Deliverable | Status |
|---|---|---|
| Constructed 576-row matrix follows classifier design | Preserve as analytical enumeration, report derivation; separate actual component execution | Baseline preserved |
| Practical assurance scenario and unsupported interpretation | Show healthy operational label during controlled violation of a named policy; do not allege observed human misuse | Pilot implemented |
| Exact PQ, identity and validator assumptions | Native handshake/fallback trace, real sync admission challenge, actual consensus votes; document trust boundaries | Consensus pilot only |
| Gate matches oracle by construction | Compare metadata-only classifier, semantic predicate gate and a distinct observed-evidence gate; do not use scenario truth as gate input | Planned |
| Runtime evidence, statistics, latency | Retain raw traces, execution provenance, independent experimental units; no inference from repeated deterministic orderings; measure local overhead separately from V2X latency | Pilot planned execution |
| Code/data availability and DOI | Freeze final executable revision and deposit reproducibility artifact; match manuscript and portal statements | Pending |
| Figures, equation, references, affiliation, funding and COI | Verify against reviewer letter and exact manuscript before final point-by-point response | Pending |

## RQ1 pilot: validator assumption

Use the actual Python PermissionedConsensusEngine, configured with three enrolled
lab validators and threshold two. External policy truth is an authored test
label: allowed or disallowed. Honest votes follow that label; zero through
three controlled identities approve regardless. Each fresh engine runs signed
votes in one of 12 seeded orders. The runtime classifier receives actual
component metadata inside a constructed healthy transport snapshot, not a live
dashboard capture. Positive controls must accept allowed proposals; disallowed
proposals without controlled quorum should reject. A disallowed proposal
accepted by a controlled quorum demonstrates the bounded policy assumption,
not a defect in quorum arithmetic or proof of deployed compromise. The classifier
is not claimed to assert validator honesty; the study tests potential
overinterpretation of the operational label. No cryptographic novelty is claimed.

96 scheduled cells/runs (12 orders x 4 control counts x 2 policy labels).
Orders are repeated design variations, not 96 independent deployments.
Report cell counts and raw transitions descriptively. The execution interval
is local sign-and-submit time, not wireless latency. No statistical significance
or security proof from this pilot. Keep all outcomes.

Run:
    python -m unittest tests.test_claim_validation_consensus_probe -v
    python -m experiments.claim_validation.consensus_probe --out claim-results/consensus

Next: actual sync enrollment and native ML-KEM/fallback probes; live metadata
capture with explicit source/epoch/time binding; independent evidence collector
and withheld-claim policy; frozen confirmatory protocol with negative controls,
matched baselines, uncertainty and overhead. Review novelty against primary
assurance/attestation literature before asserting any contribution.

## RQ1 pilot: identity admission and declared configuration

Six deliberately constructed configurations cross actual registry presence,
explicit global compatibility flag, and declared identity policy (including
two inconsistent declarations). Four credential/identity conditions, four
fresh local engines per cell: 96 scheduled runs. Real SyncServer handshake
handler, authenticated acknowledgement and session binding are observed
without opening sockets. Isolated synthetic keys are never exported.
Record the declared metadata, actual outcome and real runtime monitor events.
Contrast the alert-free constructed snapshot with one including observed
alerts. This distinguishes the meaning of configured admission metadata from
actual per-identity admission; an explicit lab compatibility mode is not a
production security guarantee. Do not infer physical identity uniqueness or
Sybil resistance from a successful negative challenge. Repetitions descriptive.

Consensus pilot observed: see claim-validity-consensus-pilot-observed.md.
Identity pilot execution pending exact-head CI.

## Identity pilot correction and PQC pilot

CI run 45390934835: five identity tests passed, one failed because the
experiment expected RISK for a HANDSHAKE_REJECTED event. The actual monitor
classifies that event MEDIUM, and the operational classifier returns GUARDED.
Correct the expectation without modifying production behaviour; record this
as a pilot protocol correction. The identity campaign was skipped in that run.

The next pilot runs real DynamicCryptoAgilityLayer client/server methods with
a pinned liboqs native library and Python bindings. Six configurations (eight
fresh pairs per condition, 48 runs): ML-KEM-512, forced ECDH, forced PSK,
injected missing provider with/without ECDH, malformed KEM offer with ECDH
disabled. Confirm session key agreement internally without recording secrets.
Record actual negotiated mode vs static capability declaration and operational
posture. Provider absence is a deliberate module injection. PSK fallback is
an existing explicit implementation path; ECDH disabled does not imply PQ-only
or session fail-closed. This is local Python handshake execution with native
crypto, not the separate C++ ledger, authenticated network capture, or a
cryptographic security proof. No simulated positive result accepted.
Repeated fresh keys measure execution variability, not independent deployments.


## Runtime observation acquisition

A separate local observation module now reads actual component outputs, never
declared security capability metadata or experimental truth labels. Handshake
observations compare session establishment and agreement; identity observations
record authenticated acknowledgement, server binding and membership; consensus
observations record actual epoch, threshold, votes and status, not validator
honesty. Each exported record has a trial scope, monotonic timestamp, typed facts
and SHA-256 digest. Same-process age/scope checks are available. The digest is
not a signature; the observer is not a separate trusted principal, and
observations are not remote attestation or durable replay protection. The next
stage must independently bind trusted evidence to a claim and explicitly
withhold unverifiable assumptions. Exact-head execution pending.


## Claim-specific eligibility prototype (exploratory)

For each claim q, E(q) = O_strong AND G(q, observation). The gate uses
typed, scope-bound, fresh same-process observations; it never reads fault
scenario labels or controlled-voter counts. It returns ELIGIBLE,
NOT_SUPPORTED, or WITHHELD, with an explicit reason. Operational posture
is retained unchanged. ML-KEM claim requires matched session and both
peers reporting actual PQC mode and ML-KEM-512; enrolled session requires
authenticated acknowledgement and registry membership; recorded quorum
acceptance requires a consistent accepted tally. Validator honesty and
external policy validity are always withheld under tally-only evidence.
These latter claims are not incorrectly treated as false just because
they cannot be observed. No global Sybil, PQ, Byzantine or physical
safety claim. No external attestation: the local observer is trusted.
One-second max age is a provisional lab parameter, not a validated SLA.
Export digest is not proof of origin. All three probes now record both
legacy posture and scoped eligibility. This is an exploratory comparison
and does not independently establish effectiveness: the eligibility
predicates deliberately use the same observed component facts as the
narrow local claims. Next: independently adjudicated paired evaluation,
metadata disagreement and evidence faults, coverage/abstention trade-off
and overhead. Preserve negative and unknown outcomes. CI pending.
