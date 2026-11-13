# OmniGuard V2X research evidence status

Updated: 2026-11-13. This is a **claim-gated status matrix**, not a finished paper.
Distinguish implemented code, observed source-data analysis, deterministic
software verification and independent empirical research.

| Workstream | Status | Verified engineering/source evidence | Remaining scientific gate |
| --- | --- | --- | --- |
| Hardware TCP ingress, bound messages, authenticated node sessions, replay and safety gate | MERGED; SERIAL QUARANTINE DRAFT PR #98; LAB VALIDATION BLOCKED | PR #74 was merged; source regression and GitHub security CI addressed software controls | Physical Pi/CAN bench and local emergency safety case not independently verified |
| V2X event admission | MERGED SOFTWARE PROTOTYPE | PR #80 merged opt-in off/shadow/enforce, authenticated-session-before-quorum policy; command-smuggling regression tests | Independent incident labels, prior-art originality analysis, correlated reporters and physical safety validation |
| Network collusion and availability fault checks | NEW DRAFT PR #89 (issue #88) | Actual merged EvidenceAdmissionGate and research-only ConsistentSubsetAdmissionGate exercised on 13 scripted incidents with seed/jitter variations, selected-source roles and SHA manifests | Constructed fault models, not independently captured physical incidents or repeated simulator trials; published comparator and HIL evidence missing |
| Source-CAM integrity | VERIFIED IMPORT, not event truth | PR #82 merged; official VeReMi NextGen v1.0.0 baseline and dataReplay archives SHA-verified and imported; receiver duplicates audited | CAM attacker bit does not mean a verified hazard incident or physical source attestation; distribution license review |
| Auxiliary Highway CAM detection | DRAFT PR #85, REPRODUCED | Official SHA-verified Highway_2 dataReplay single-source Test: 18,892 unique fingerprints; temporal comparator F1 25.05% (post-hoc) | Untouched independent simulator/split, published detectors, uncertainty; no incident truth |
| Auxiliary Urban transfer | DRAFT PR #87, EXPLORATORY REPRODUCED | Fixed Highway Validation thresholds transferred to Urban_2 Test (113,779 fingerprints), source SHA verified, temporal comparator F1 26.06% | Only one new scenario; source selection after Highway results; no independent seeds or confirmatory significance |
| Incident truth and split hygiene | STRUCTURAL ONLY | PR #83 merged structural source/group split audit | Independent world-state incident labels, label-review procedure, source license and temporal leakage still unverified |
| Realistic in-vehicle CAN source | BLOCKED | No licensed original CAN trace linked to independently annotated V2X hazard state | Verify source, license, timing, physical attack model and authorization boundary |
| Ledger crash safety and contract finality | DRAFT PR #90 — LOCAL CHECKPOINT RESEARCH ONLY | Experimental `experiments/ledger/crash_checkpoint.py` verifies local Go snapshots, fsyncs temporary files, uses atomic replacement and POSIX directory fsync; 10 fault-injection tests include real subprocess exits | Not wired into production Go persistence; no real power-loss/HIL validation, server-signed receipt finality or trusted monotonic host-rollback anchor |
| Statistical validation | TOOLING ONLY | PR #77/#78 merged exploratory no-false-significance reporting, paired bootstrap/sign-flip/Holm code | Independent seed execution, preregistered analysis, baseline/ablation comparisons, CIs/effect sizes using **actual** incident data |
| Runtime scaling and network availability | UNVERIFIED | Existing quick unit and deterministic simulation tests are not a representative runtime benchmark | Real network delays/partitions with measured CPU/RAM/tail latency and physical isolation |
| Novelty and paper evidence | NOT ESTABLISHED | Evidence-gated multi-source corroboration is a mechanism candidate, **not** new cryptography | Published prior-art comparison, distinguishable formal claim, valid ablations, reproducible multi-scenario independent datasets |

## Arduino serial ingress follow-up (draft, unverified)

The `bound-arduino-serial-telemetry` branch adds a configurable 64–65536-byte
complete-line limit (4096-byte default) and strict UTF-8/JSON-object decoding
before serial telemetry is processed. Eight in-memory regression cases cover
normal, empty, truncated, oversized, invalid UTF-8, non-object, non-finite JSON and invalid
limit inputs. The initial patch accidentally used a literal backslash-n delimiter and incorrectly escaped test fixtures; both were repaired in follow-up commits. Tests have not yet been executed in a Python environment;
CI verification is required. This does **not** authenticate an Arduino or
protect against forged but syntactically valid telemetry. Serial source
identity, physical actuation safety, and independently wired emergency
control remain blocked pending authorized hardware validation.

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

## 2026-11-13 serial framing follow-up (draft PR #98)

- **Completed in branch, awaiting CI:** `SerialFramingDesynchronized` stops the Arduino bridge when an oversized or incomplete serial frame loses its boundary. The bridge no longer resumes at an attacker-controlled fragment and requires an explicit restart. Added overflow-with-following-valid-frame and partial-timeout regression cases. This is an availability trade-off: malformed serial input can now stop remote telemetry, but it cannot bypass a separate local emergency-stop circuit.
- **Partial:** Byte limits, strict UTF-8, JSON object and nonfinite rejection exist in PR #98. Arduino serial source authentication and safe restart/recovery are not implemented.
- **Blocked:** No physical Arduino, independent emergency circuit, CAN bus or hardware fault-injection evidence available. No vehicle safety claim.
- **Upcoming:** Validate the regression suite and implement authenticated Arduino framing plus explicit resynchronization policy before physical bench tests. Research results still require independent incident truth and matched baselines.

- 2026-11-13 serial ingress follow-up (PR #98): fixed regression fixture to contain actual newline bytes; ensured serial port closes on desynchronization and all other exits. Synthetic tests/CI required before merge. No serial source authentication or physical E-stop evidence.
