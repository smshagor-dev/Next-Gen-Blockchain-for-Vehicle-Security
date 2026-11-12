# Research hypothesis and ablation protocol: V2X source-order poisoning

**Current status:** SOFTWARE MECHANISM CANDIDATE + DETERMINISTIC THREAT-MODEL
TESTS ONLY. Not a completed original scientific contribution, validated
safety property or publication-grade experiment.

## Research question and proposed mechanism

Consider a network incident relay which receives session-MAC-verified
reports from previously enrolled but potentially compromised vehicles.
The original quorum gate stores the **first** report's location/time
as reference for all future votes. A malicious enrolled node that gets
the same incident identifier first can plant a conflicting reference
position and deny honest mutual corroboration.

The research-only consistent-subset policy stores at most 16 distinct
authenticated enrolled identities per incident and searches for an
all-pairs-consistent subset of quorum size 2..4. Corroboration checks:
same event class, absolute observation timestamp differences at most
5 seconds, geodesic distance at most 100 metres, distinct sender
identities and distinct self-reported observation digests. Decisions
retain the same bounded 20-second incident TTL and 2,048-incident
default pool as the original policy.

This is a **multi-source consistency idea**, not a new cryptographic
primitive. Novelty relative to prior position consistency, trust,
multi-reporter and VANET misbehavior-detection work is **not verified**.

## Falsifiable hypotheses (to be preregistered before real data)

- **H1, first-writer robustness**: with one malicious enrolled reporter
  arriving before two mutually consistent honest reporters, a
  subset-consistency candidate relays the honest-subset incident while
  the single-anchor gate can suppress the same true alert.
- **H2, residual Byzantine limitation**: two colluding enrolled identities
  with fabricated consistent evidence can pass a quorum of two under
  *both* algorithms. Neither provides Sybil resistance, honest quorum
  guarantees or sensor-source attestation.
- **H3, partition availability**: when an actual hazard has fewer than
  two delivered honest reports, quorum policies may suppress the alert.
  The network gate must never withhold independent local emergency
  braking. These tests do not establish physical local control safety.
- **H4, resource bound and saturation**: each incident pool holds at most
  16 reporter observations. With quorum at most four, subset search has
  a capped worst case of C(16,4)=1,820 candidate subsets, and each
  candidate requires at most 6 pair comparisons. However, an attacker
  that fills the incident pool first can block all later honest reports.
- **H5, order resistance under valid source set**: if a consistent honest
  quorum fits within an unexhausted pool and the incident TTL, acceptance
  should not depend on an unrelated adversarial report arriving first.
  This is narrower than full network order invariance.

## Software properties under explicit preconditions

P1. An **accepted** research candidate event has at least quorum mutually
consistent source observations with distinct enrolled identities and
non-repeated source hashes. The hub MUST separately verify session MAC,
enrolled source binding, replay nonce and timestamp before calling either
gate. This module is intentionally not wired into V2XHub.

P2. At most one network relay per incident during the configured
time-to-live window. This does not prove persistent replay immunity
across TTL expiry and restarts.

P3. Both policy variants have finite, explicit incident/report capacity.
Rejection at capacity is fail-closed but may deny true remote incidents.

P4. Reports containing remote ECU/brake command fields are rejected by
the exact payload schema; neither admission algorithm can authorize
physical actuation. Independent local safety fallbacks require their
own system-level HIL tests.

P5. A first malicious report can change original-policy accepted
reference location, while an eligible mutually consistent subset is
allowed to supersede a contradictory reference in the research variant.
The variant does not guarantee honest sources form the subset.

These are code properties under an assumed authenticated input
interface, **not** proven global automotive or consensus safety.

## Controlled constructed scenario audit

Execute the identical 13 incident cases for authentication-only forwarding,
first-reference quorum 2, quorum 3, wide-radius 10 km and
consistent-subset quorum 2. The source scenarios exercise one enrolled
liar, two colluders, repeated identity, copied digest, source-first
incident-ID preemption, spatial/time disagreement, command smuggling,
unverified transport, loss of honest corroboration and partition.

Run 12 deterministic seeds that vary **only a small timing jitter**.
These are repeated code-path checks, not 12 independent simulations,
12 randomly sampled vehicle deployments or scientific effect estimates.
The campaign emits synthetic trace decisions and SHA-256 manifests.
The policy under test is the actual Python implementation, not hard-coded
outcome numbers.

A **malicious-assisted accepted incident** is identified separately
from ordinary incident-level true-positive counts. A report coinciding
with a true underlying hazard does not prove honest corroboration
if the selected subgroup contains compromised identities.

## Required external evidence before original research claims

1. Freeze an independent incident-ground-truth definition derived from
   simulator world state, not VeReMi CAM attacker=1, manual arbitrary
   flags or names. Version and audit labels.
2. Verify enrolled physical source identities and captured MAC/replay
   events. Evaluate unknown enrollment, colluding source cohorts and
   untrusted receiver claims.
3. Preregister event load, reporter density, geospatial uncertainty,
   quorum, capacity, stochastic radio drops, partitions, attacker
   budget and holdout splits before seeing output distributions.
4. Measure true/false incident admission, availability, time-to-alert,
   tail latency, CPU, memory and saturation across independent simulator
   seeds and distinct scenarios. Compare published multi-source trust/
   misbehavior models and full ablations under identical traces.
5. Perform formal safety analysis of local emergency controls and
   physical HIL isolation. Keep any remote evidence gate incapable
   of delaying immediate local hazard responses.
6. Report paired independent-study uncertainty, effect sizes and
   negative results, and compare to the actual prior literature.

**Current publication flag: false.** No scientific efficacy or novelty
conclusion is justified by this scripted software campaign.
