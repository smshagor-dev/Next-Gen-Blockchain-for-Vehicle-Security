# OmniGuard V2X research evidence status

Updated: 2026-11-12. This is a **claim-gated status matrix**, not a finished paper.
Distinguish implemented code, observed source-data analysis, deterministic
software verification and independent empirical research.

| Workstream | Status | Verified engineering/source evidence | Remaining scientific gate |
| --- | --- | --- | --- |
| Hardware TCP ingress, bound messages, authenticated node sessions, replay and safety gate | MERGED, LAB VALIDATION BLOCKED | PR #74 was merged; source regression and GitHub security CI addressed software controls | Physical Pi/CAN bench and local emergency safety case not independently verified |
| V2X event admission | MERGED SOFTWARE PROTOTYPE | PR #80 merged opt-in off/shadow/enforce, authenticated-session-before-quorum policy; command-smuggling regression tests | Independent incident labels, prior-art originality analysis, correlated reporters and physical safety validation |
| Network collusion and availability fault checks | NEW DRAFT PR #89 (issue #88) | Actual merged EvidenceAdmissionGate and research-only ConsistentSubsetAdmissionGate exercised on 13 scripted incidents with seed/jitter variations, selected-source roles and SHA manifests | Constructed fault models, not independently captured physical incidents or repeated simulator trials; published comparator and HIL evidence missing |
| Source-CAM integrity | VERIFIED IMPORT, not event truth | PR #82 merged; official VeReMi NextGen v1.0.0 baseline and dataReplay archives SHA-verified and imported; receiver duplicates audited | CAM attacker bit does not mean a verified hazard incident or physical source attestation; distribution license review |
| Auxiliary Highway CAM detection | DRAFT PR #85, REPRODUCED | Official SHA-verified Highway_2 dataReplay single-source Test: 18,892 unique fingerprints; temporal comparator F1 25.05% (post-hoc) | Untouched independent simulator/split, published detectors, uncertainty; no incident truth |
| Auxiliary Urban transfer | DRAFT PR #87, EXPLORATORY REPRODUCED | Fixed Highway Validation thresholds transferred to Urban_2 Test (113,779 fingerprints), source SHA verified, temporal comparator F1 26.06% | Only one new scenario; source selection after Highway results; no independent seeds or confirmatory significance |
| Incident truth and split hygiene | STRUCTURAL ONLY | PR #83 merged structural source/group split audit | Independent world-state incident labels, label-review procedure, source license and temporal leakage still unverified |
| Realistic in-vehicle CAN source | BLOCKED | No licensed original CAN trace linked to independently annotated V2X hazard state | Verify source, license, timing, physical attack model and authorization boundary |
| Ledger crash safety and contract finality | PR #90 MERGED; GO /save PATCH IN REVIEW (issue #95) | Merged Python checkpoint research tests verified local snapshots; new Go `/save` no-delete atomic replacement, POSIX parent-directory fsync and serialized authenticated saves are implemented on a separate branch with native Go regression tests | Only explicit saves persist; startup recovery, multiple writers, hardware power-loss/HIL, receipt finality and trusted rollback anchors remain unverified |
| Statistical validation | TOOLING ONLY | PR #77/#78 merged exploratory no-false-significance reporting, paired bootstrap/sign-flip/Holm code | Independent seed execution, preregistered analysis, baseline/ablation comparisons, CIs/effect sizes using **actual** incident data |
| Runtime scaling and network availability | UNVERIFIED | Existing quick unit and deterministic simulation tests are not a representative runtime benchmark | Real network delays/partitions with measured CPU/RAM/tail latency and physical isolation |
| Novelty and paper evidence | NOT ESTABLISHED | Evidence-gated multi-source corroboration is a mechanism candidate, **not** new cryptography | Published prior-art comparison, distinguishable formal claim, valid ablations, reproducible multi-scenario independent datasets |

## Research assertion / results gate

- Real VeReMi CAM results are **auxiliary message-manipulation detection**
  observations, not experiments proving false hazard-event admission rates.
- Thirteen scripted adversarial incident cases include single/multiple malicious
  enrolled identities, incident-ID first-writer preemption, copied digest,
  session-unverified report, repeated identity, displaced/stale reporters,
  remote-action-field smuggling and lost honest corroboration. These are
  deterministic **software verification** only, not independent research.
- The campaign's apparent scenario rates must never be presented as
  detection accuracy, model uncertainty, independent statistical samples,
  vehicle safety, post-quantum security or a publication-grade result.
  Deliberately failing cases (colluding malicious quorum, partition-induced
  missed true alerts) are essential negative evidence, not benchmarks.
- The bounded **consistent-subset** research alternative removes first-reporter
  location/time reference dependence for compatible honest subsets. It is not
  integrated into V2XHub and is still vulnerable to malicious collusion,
  report-pool exhaustion and lost honest corroboration. A constructed scenario
  demonstrating the difference is **not** proof of originality or superiority.
- No physical hardware, external vehicle, road test, or HIL evidence has
  been observed in this session. No vehicle actuation is performed.
- A later paper may use only immutable verified actual-source evidence with
  source/metric mapping, defensible independent units, accurate citations,
  comparative baselines, uncertainty and limits. A software QA report is
  **not** an original research paper.

## Next substantive code tasks

1. Build a verified incident-level world-state annotation bridge, keeping
   original VeReMi CAM attacker labels separate and explicit provenance.
2. Turn constructed source-enrollment, collusion, preemption, report-pool
   saturation and network-partition cases into independently executed,
   externally verified incident traces; quantify false accepts and missed
   honest hazards under identical candidate/baseline conditions.
3. Replace scripted truth and delivery flags with authenticated captured
   sessions and independently verified simulation world truth.
4. Run matched published comparators and multiple independently simulated
   seeds/scenarios, pre-register hypotheses, preserve raw evidence and
   evaluate uncertainty/effect sizes before writing numeric manuscript claims.

## Local Go ledger crash-checkpoint evidence boundary (PR #90)

The research-only local checkpoint validates snapshot block hashes against the
existing Go ledger verifier before writing and refuses a different historical
prefix relative to the **currently available** checkpoint. A bounded JSON
checkpoint is written to a temporary file, flushed/fsynced, atomically
replaced and directory-fsynced on POSIX. Fault-injection tests include actual
POSIX subprocess `os._exit(73)` at three durability stages, malformed and
truncated checkpoints, generation mismatch and recovery of complete old/new
states. These verify software behaviour on the tested OS/filesystem, **not**
physical power-loss durability or distributed consensus finality.

Two deliberate failure cases must remain visible: a host can restore a valid
older checkpoint after restart because no externally trusted monotonic anchor
exists, and unkeyed SHA-256 hashes can be recomputed over forged receipt
metadata. Hence the prototype provides neither cryptographically authenticated
smart-contract finality nor host-rollback resistance. No HIL/vehicle safety
claim or submission-ready experimental result follows from these tests.

## Production Go /save crash-consistency follow-up (issue #95)

The original Go route deleted the prior valid saved chain after a failed
rename before retrying. This can destroy the only committed snapshot under
further failure. The new implementation never unlinks the destination,
synchronizes temporary file contents before one replacement attempt and
syncs its parent directory on POSIX. Same-server concurrent saves are
serialized and invalid in-memory blockchain snapshots are not saved.
Tests must verify rename failure retains original bytes, simulated
post-rename sync errors report **uncertain durability**, and signed API saves
write intact JSON with restrictive permissions. No automatic block-by-block
durability or startup recovery has been implemented. No software tests alone
establish disk power-loss behaviour, HIL safety, host rollback resistance or
distributed transaction finality. See `docs/go-ledger-save-durability.md`.
