# V2X incident admission evidence ledger

Updated: 2026-11-12. This file records engineering implementation and **missing
scientific evidence** without interpreting CI tests as research experiments.

| Area | State | Concrete evidence | Research gap |
| --- | --- | --- | --- |
| Authenticated V2X transport | EXISTING | Existing signed HELLO, per-session MAC, timestamp/replay checks in v2x_protocol.py | Network-level fault injection, identity/key lifecycle and revocation remain separate controls |
| Evidence-gated remote event admission | IMPLEMENTED IN DRAFT PR (not independently field validated) | v2x_evidence_admission.py; pending-to-accepted quorum, distinct enrolled source identity, time/distance consistency, bounded memory, one relay per incident | External baseline comparison, collusion tests, correlated reports, data association errors |
| Safety-isolated integration | IMPLEMENTED IN DRAFT PR (software only) | V2XHub off/shadow/enforce after verified session; no CAN/brake/ECU calls, local safety path unchanged | Real actuator bench isolation / system safety review not performed |
| Local regression tests | RUNS WHEN CI COMPLETE | tests/test_v2x_evidence_admission.py and tests/test_v2x_admission_replay.py; dedicated workflow | Tests use fabricated deterministic inputs and do not support performance claims |
| Offline replay comparison | IMPLEMENTED IN DRAFT PR | experiments/v2x/evaluate_admission.py: incident-level auth-only, quorum-2, quorum-3, 10km radius ablation | Input captures/labels are not independently attested; no actual VeReMi/CAN dataset evaluated |
| Paper hypotheses and safety boundary | PROPOSAL ONLY | paper/v2x-admission-research-protocol.md | Prior-art survey, originality determination, preregistered hold-out experiment required |
| Multi-seed paired scientific inference | SEPARATE DRAFT PR #78 | Paired statistical comparator; no real empirical results | Merge verified tooling later; independently execute paired runs with labels/provenance |
| FL significance integrity | SEPARATE DRAFT PR #77 | False n>=30 significance removed with tests | No real multi-run FL evidence; outside this paper's core scope |
| Physical Pi/ECU interlock | SEPARATE DRAFT PR #74 | Authenticated Pi telemetry, bench gate, replay defenses; dedicated tests | Real bench/HIL validation and safety review unavailable |
| Authentic external V2X dataset | NOT STARTED | No source-approved data imported by this branch | Verify VeReMi NextGen metadata/license, mapping to incident-level labels and distinct corroborators |
| Statistical results | NOT ESTABLISHED | No independent real-world experimental seeds or uncertainty estimates | Run pre-registered external experiments and publish raw evidence/negative results |
| Submission-ready original paper | BLOCKED | New mechanism candidate is a hypothesis, not a novelty proof | Prior art, external data, real baseline/ablations, effect sizes, safety and availability trade-offs required |

## Evidence hygiene

- CI and synthetic unit-test cases only establish software behavior.
- The offline adapter's session_verified and ground_truth flags are supplied
  by input traces; the adapter does not verify MACs from captured packets.
- Sensor digests are self-reported; evidence coincidence does not prove
  independent physical sensors, and compromised enrolled nodes can collude.
- Pending true hazards are intentionally *not* forwarded in enforce mode:
  quantify the resulting missed remote alert rate and latency.
- Off remains the default until real evaluation and safety review.
