# Prospective held-out software evaluation protocol

Status: protocol specification only, no held-out results collected.
Existing 240 trials and all derived replays remain development data.
This protocol is prospective relative to the proposed new campaign, not
preregistration of the earlier observed results.

## Fixed candidate and outcome definitions

Freeze claim_gate.py and runtime_evidence.py at commit
5a5e0851496f31e4afd626aeee218b0aeab66cb5 before new outcomes. Verify file
hashes against that revision. Any change requires a separately versioned
protocol and a fresh evaluation; do not overwrite failed results.
Keep the claim meanings narrow: recorded quorum acceptance, enrolled
session, and negotiated ML-KEM-512. Never infer honest majority, physical
identity, or global post-quantum security from these outcomes.

## New software conditions (runner not yet implemented)

- Consensus: new 4-, 5- and 7-member configurations; independently chosen
  quorum fractions 1/2 and 2/3, votes on both sides of the threshold,
  epoch mismatch and duplicate-vote rejection controls.
- Identity: new multi-member registries of sizes 2 and 8, enrolled and
  unlisted identities, correct and incorrect credentials, no-registry
  default deny, and explicit lab compatibility controls.
- Handshake: fresh process pairs, ML-KEM-512 positive, ECDH and PSK
  fallback, failed completion (separate context or mismatched key),
  with authentic provider build and no simulated positive result.

Before running, implement a versioned finite schedule with exact case
IDs, replication budget, deterministic allocation, test-only ephemeral
credentials and independent expected outcomes, and commit its digest.
Use fresh processes for experimental units, not repeated replays as
independent units. Explicitly distinguish new design cells from stochastic
timing measurements. No network, hardware or external attestation claim.

## Evaluation plan

Primary endpoint: unsupported eligibility among negative reference trials.
Secondary: supported eligibility among positive trials, withheld fraction,
non-supported fraction, coverage, and paired local decision overhead.
Compare posture proxy, declared capability proxy and unchanged candidate.
Report each claim domain and design cell separately. Retain all errors,
timeouts and reference disagreements; investigate before interpretation.
Report descriptive fixed-design contrasts, no population confidence
intervals or significance tests without a defensible sampling frame.
The timing benchmark is separate from end-to-end latency.

## Release gates

Implement and review exact schedule before running it; record software
hashes, dependency versions, environment, raw traces, all reference
disagreements, and failure status. Independent external adjudication and
published comparator remain separate open requirements. Do not tune the
candidate on this evaluation and call the same observations held-out.


## Schedule freeze and execution implementation

Frozen schedule commit 93c5a6f03cac21076041767efbda58b5dfaf6ccd,
Git blob 71e8ef83e27463c0940f9e7698b5d522d8622cb5. 41 cells, two replicates
per cell, 82 scheduled trials (48 consensus, 24 identity, 10 PQC).
The runner verifies the schedule and both candidate source blobs before
execution. Expected labels are not transmitted to the worker; the parent
checks direct outcome against the fixed design. Each trial is a fresh
subprocess with ephemeral keys; both handshake peers reside in that
subprocess rather than separate network processes. Context mismatch and
missing context cover failed session confirmation. No external observation
principal or actual socket is claimed. Every scheduled result, timeout,
disagreement and worker failure is recorded; nonzero failure status.
This finite design is new relative to the pilots, not a random sample of
deployments. Timing in the worker is illustrative single-call measurement;
the separate block benchmark is the main overhead measurement.
No held-out results have yet been verified.

## First observed execution

See claim-validity-heldout-observed.md for the CI-observed results. A separate artifact audit job now regenerates figures and tables from downloaded raw traces; execution pending.
