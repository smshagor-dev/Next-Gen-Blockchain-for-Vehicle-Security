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


## Paired exploratory baseline and fault replay protocol

Three narrow claims are compared on the same actual-component trial records:
ML-KEM-512 negotiation, enrolled-session admission, recorded quorum acceptance.
Original posture proxy treats STRONG as eligibility (a hypothetical user
interpretation, not a claim made by the original classifier). The declared
capability proxy additionally requires the corresponding self-reported
capability, registry policy or quorum configuration. This is an explicitly
constructed metadata-only comparator, not the original manuscript's exact
semantic-flag oracle or a published baseline. The observed gate receives
scoped local facts. An offline ablation removes only expected scope and
freshness checks. Ground truth is separately exported actual outcome fields
from the same process, not gate output, but is not independent attestation.
The broad validator-honesty and policy-validity claims remain withheld and
are not conflated with recorded quorum acceptance.

For each base trial apply eight replay conditions: clean, missing, stale,
future-dated, wrong-scope, wrong-kind, malformed facts, and flipped declared
capability predicate. The replay clock is synthetic, not measured clock
failure. The last condition changes only the metadata predicate, not the
underlying operational posture. Integrity-check trace manifest and per-record
digest; record the expected scope separately. Digest and scope labels are not
authentication. Total planned base trials 240, paired fault rows 1920,
four method decisions per row. These are repeated interventions, not
independent observations. Report eligible supported/unsupported counts,
withheld and not-supported separately, positive eligibility rate, negative
unsupported rate, and coverage. Undefined class denominators remain null.
Do not pool across distinct claims or claim statistical significance.
Independent adjudication, observer compromise sensitivity, exact manuscript
semantic baseline, related work comparison and overhead remain open.


## Separate design reference and observer sensitivity

Freeze a distinct reference implementation from the explicit experimental
design: recompute consensus transitions from vote order and assigned policy,
use a table of admitted identity/credential conditions, and preassign the
expected handshake mode for each provider condition. Compare the design
expectation to direct component outcomes and preserve disagreements. No
import from the proposed gate or observation collector in the reference
module. This separates implementation paths, not trust principals, and is
not blinded independent adjudication. It follows already observed pilot
conditions, so it is exploratory and must not be called preregistered.

For the same 240 base trials, replay eight existing evidence faults with
the design reference, and add one hypothetical schema-consistent contrary
observation per trial to expose the trusted-observer limitation. Original
posture stays unchanged. No deployment interface is exercised by this
sensitivity intervention. Report false eligibility and loss of true
eligibility separately. A digest is not evidence of trusted origin.

Report gate-minus-comparator eligibility contrasts separately by claim,
fault and reference class, equal-weighting the authored design cells.
Repeated seeds, keys and fault interventions are not independent samples.
Show per-cell deltas and range, not confidence intervals or p-values that
would falsely treat deterministic repetitions as independent deployments.
38 design cells (8 consensus, 24 identity, 6 PQC); 1920 paired replay
rows plus 240 sensitivity rows planned. Exact-head CI pending.
External adjudication, new held-out independent experimental units,
published comparator and timing sensitivity remain unresolved.


## Performance and freshness sensitivity

Compare only predecoded local decision-stage cost on matched observations:
posture proxy, declared-capability proxy and observed gate. Equal warm-up,
30 blocks per domain, 10 passes over the same domain trials per method and
block, fixed randomized trial and method order. Record raw block durations
and eligibility counts, median of block means, and paired block differences.
These are local decision microbenchmarks, not V2X RTT, cryptographic
throughput, evidence-collection cost, or individual-call tail latency.
For 240 base records, planned timing decisions 216000 across all methods.

Sweep 5 max-age thresholds (1, 10, 100, 1000, 5000 ms) against 8 synthetic
age offsets (-1, 0, 1, 10, 100, 1000, 5000, 10000 ms), for 9600 replay rows.
These offsets are not a measured real-delay distribution; no optimized
freshness SLA is inferred. Keep all results and retain per-class counts.
See claim-validity-heldout-protocol.md for prospective evaluation design;
exact schedule and runner must still be implemented before execution.


## Held-out runner implementation

Exact finite schedule committed before execution; see
claim-validity-heldout-protocol.md. 82 fresh-subprocess trials over 41
new design cells; the candidate remains unchanged and checked by Git blob.
Independent parent-side expected labels and direct outcome checks, raw
JSONL, execution status and provenance retained. Exact-head CI pending.
