# OmniGuard V2X research evidence status

Updated: 2026-11-12. This is a **claim-gated status matrix**, not a finished paper.
Distinguish implemented code, observed source-data analysis, deterministic
software verification and independent empirical research.

| Workstream | Status | Verified engineering/source evidence | Remaining scientific gate |
| --- | --- | --- | --- |
| Hardware TCP ingress, bound messages, authenticated node sessions, replay and safety gate | MERGED, LAB VALIDATION BLOCKED | PR #74 was merged; source regression and GitHub security CI addressed software controls | Physical Pi/CAN bench and local emergency safety case not independently verified |
| V2X event admission | MERGED SOFTWARE PROTOTYPE | PR #80 merged opt-in off/shadow/enforce, authenticated-session-before-quorum policy; command-smuggling regression tests | Independent incident labels, prior-art originality analysis, correlated reporters and physical safety validation |
| Network collusion and availability fault checks | NEW DRAFT (issue #88) | experiments/v2x/adversarial_admission_campaign.py executes policy under twelve fixed synthetic cases, seed/jitter variations, hash manifests and tests | These are scripted fault models, not independently captured incidents or repeated experiments; real labelled fault trials missing |
| Source-CAM integrity | VERIFIED IMPORT, not event truth | PR #82 merged; official VeReMi NextGen v1.0.0 baseline and dataReplay archives SHA-verified and imported; receiver duplicates audited | CAM attacker bit does not mean a verified hazard incident or physical source attestation; distribution license review |
| Auxiliary Highway CAM detection | DRAFT PR #85, REPRODUCED | Official SHA-verified Highway_2 dataReplay single-source Test: 18,892 unique fingerprints; temporal comparator F1 25.05% (post-hoc) | Untouched independent simulator/split, published detectors, uncertainty; no incident truth |
| Auxiliary Urban transfer | DRAFT PR #87, EXPLORATORY REPRODUCED | Fixed Highway Validation thresholds transferred to Urban_2 Test (113,779 fingerprints), source SHA verified, temporal comparator F1 26.06% | Only one new scenario; source selection after Highway results; no independent seeds or confirmatory significance |
| Incident truth and split hygiene | STRUCTURAL ONLY | PR #83 merged structural source/group split audit | Independent world-state incident labels, label-review procedure, source license and temporal leakage still unverified |
| Realistic in-vehicle CAN source | BLOCKED | No licensed original CAN trace linked to independently annotated V2X hazard state | Verify source, license, timing, physical attack model and authorization boundary |
| Ledger crash safety and contract finality | PARTIAL | Prior source security hardening exists; mock contract success is not ledger finality | Process kill/power fault recovery, real consensus finality evidence and measured safety semantics |
| Statistical validation | TOOLING ONLY | PR #77/#78 merged exploratory no-false-significance reporting, paired bootstrap/sign-flip/Holm code | Independent seed execution, preregistered analysis, baseline/ablation comparisons, CIs/effect sizes using **actual** incident data |
| Runtime scaling and network availability | UNVERIFIED | Existing quick unit and deterministic simulation tests are not a representative runtime benchmark | Real network delays/partitions with measured CPU/RAM/tail latency and physical isolation |
| Novelty and paper evidence | NOT ESTABLISHED | Evidence-gated multi-source corroboration is a mechanism candidate, **not** new cryptography | Published prior-art comparison, distinguishable formal claim, valid ablations, reproducible multi-scenario independent datasets |

## Research assertion / results gate

- Real VeReMi CAM results are **auxiliary message-manipulation detection**
  observations, not experiments proving false hazard-event admission rates.
- Twelve scripted adversarial incident cases (including single/multiple enrolled
  liar, copied sensor digest, session-unverified report, repeated identity,
  stale-separated source, displaced reporter, remote-action-field smuggling and
  lost honest corroboration) are deterministic **software verification** only.
- The campaign's apparent scenario rates must never be presented as
  detection accuracy, model uncertainty, independent statistical samples,
  vehicle safety, post-quantum security or a publication-grade result.
  Deliberately failing cases (colluding malicious quorum, partition-induced
  missed true alerts) are essential negative evidence, not benchmarks.
- No physical hardware, external vehicle, road test, or HIL evidence has
  been observed in this session. No vehicle actuation is performed.
- A later paper may use only immutable verified actual-source evidence with
  source/metric mapping, defensible independent units, accurate citations,
  comparative baselines, uncertainty and limits. A software QA report is
  **not** an original research paper.

## Next substantive code tasks

1. Build a verified incident-level world-state annotation bridge, keeping
   original VeReMi CAM attacker labels separate and explicit provenance.
2. Parameterize enrolled-node collusion, honest reporter missingness,
   time/distance disagreement, replay and saturation under controlled network
   fault models; collect time-to-alert, false-accept and false-negative traces.
3. Replace scripted truth and delivery flags with authenticated captured
   sessions and independently verified simulation world truth.
4. Run matched published comparators and multiple independently simulated
   seeds/scenarios, pre-register hypotheses, preserve raw evidence and
   evaluate uncertainty/effect sizes before writing numeric manuscript claims.
