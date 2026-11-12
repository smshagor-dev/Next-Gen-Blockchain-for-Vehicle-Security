# OmniGuard V2X: original research execution protocol (draft)

**Status: OPEN — not submission ready.** This is a prospective preregistration-style execution plan, not a report of completed experiments. It does not validate originality, certify physical vehicle safety, or supply experimental results.

## Narrow research problem

Determine whether *cryptographically authenticated, freshness-constrained, evidence-gated admission of external V2X telemetry and commands*, while keeping local safety control independently isolated, improves attacker resistance **without unacceptable rejection of legitimate safety-relevant data**. Existing authentication and policy checks are reused; a distinct mechanism (formal decision function, state transitions, security/availability objective and implementation) must be defined and literature-checked before an originality claim is made. Project-level integration alone does not establish novelty.

**Safety boundary:** Remote/distributed admission must never be placed in the critical path of independent local emergency braking. No physical actuation is permitted without an independently armed, isolated, supervised bench interlock. No road deployment or production safety claim.

## Research questions and falsifiable hypotheses

| Question | Proposed null hypothesis (not yet tested) | Endpoints |
| --- | --- | --- |
| RQ1 Adversarial authenticity | The proposed admission mechanism does not reduce unauthorized acceptance compared with an authentication-only baseline | unauthorized accept rate by attack; missed replay/spoofing; false positive and negative rates |
| RQ2 Safety/availability | Mechanism does not improve safety-policy violation rate at a fixed allowable legitimate-event rejection budget | event false-reject rate; time to decision; fail-safe state transitions; recoverability |
| RQ3 Trust continuity | Mechanism does not improve detection of revoked/rollback/compromised event provenance compared with existing policy | accepted stale/revoked events; recovery behavior; audit integrity failures |
| RQ4 Scalability | Mechanism's security gains incur no acceptable resource/performance operating point versus strongest baseline | p50/p95/p99 admission latency; CPU/RAM; bandwidth; throughput; queue/drop fraction |

Avoid qualitative claims such as *tamper proof*, *100% accurate*, *end-to-end PQ secure*, *51% resistant*, or *Sybil resistant under open admission*. Simple-majority blockchain remains outside majority-control-resistance scope unless replaced with a separately validated protocol.

## Operational baseline and attack design

1. Baselines: unauthenticated legacy receiver (offline simulated vulnerability only), authenticated-and-freshness-checked ingress, existing anomaly-only trigger, existing blockchain/trust policy, complete proposed mechanism. Compare under the **same held-out instances and seeds**; never connect the insecure baseline to actuation.
2. Ablations: disable one proposed mechanism component at a time (freshness, evidence consistency, admission policy, quarantine, revocation), while preserving independent local safety control. Do not call a reused component novel.
3. Attacks: forged/unsigned telemetry, authenticated malicious peer, timestamp/nonce replay, sybil attempts under explicitly stated admission model, adaptive low-amplitude manipulation, sensor noise/drift, bursts, delayed/out-of-order messages, dropped packets and partitions, revoked key and validator collusion limited to the chosen consensus assumption.
4. Controls: ordinary sensor variability, benign high-rate traffic, legitimate safety events, clean network and clean operation without attack. Include failures and false alarms, not only successful detections.
5. Treat V2X packet misbehavior and CAN injection as separate datasets/threat models; don't pool accuracy across domains without justified transfer protocol.

## Data integrity / provenance gate

- Candidate datasets: VeReMi NextGen (V2X), a documented CAN intrusion corpus for a separate domain, controlled synthetic network faults and explicitly labeled software/HIL bench traces.
- Before any paper result: preserve dataset license, source URL, retrieval date, version/checksum, labels, class distribution, preprocessing code and rationale. Record the exact split or split manifest. Prevent identity, time-window and attack-campaign leakage; keep held-out attack variants for generalization analysis.
- For every run record: immutable source commit, config, independent random seed, dataset/split checksums, baseline ID, attack parameters, hardware/OS/runtime, start/end timestamps, exit status, raw prediction/action trace and integrity hashes.
- Do not substitute dataset fixture or sample smoke inputs for actual observations. Missing data must remain BLOCKED, not zero or interpolated.

## Experimental design and quantitative evaluation

- Pilot first to estimate effect sizes and variability. Determine sample size from a stated power/precision calculation rather than assuming `n>=30` implies significance.
- Use matched scenario/seed comparisons and preserve per-scenario and per-attack results. Compare baselines on identical held-out traces. Count unique experimental units, not only CSV rows.
- Report confusion matrices, FPR/FNR, precision/recall/F1 (with appropriate prevalence), attack success/unauthorized acceptance and clean-event rejection. Benchmark latency distributions, end-to-end time boundaries, throughput, CPU/RAM and energy if measured.
- Report effect sizes and confidence intervals appropriate to the endpoint, apply a defensible inferential test to predeclared comparisons, correct for multiple comparisons, expose exclusions and negative results. No significance flag unless the actual test and its evidence are attached.
- Use HIL only when lab resources exist; **simulation must be labeled simulation**. No implied road or fleet test from communication-volume formulae.

## Engineering and evidence gates

| Gate | Requirement | Status |
| --- | --- | --- |
| E1 secure authenticated ingress and bench-safe command isolation | Enrolled per-device MAC, bounded replay/framing, bench gate, regression checks, physical supervision where used | IN PROGRESS — draft PR #74; unmerged / tests pending |
| E2 originality/literature | At least one precise algorithmic or testable architectural distinction, dated prior-work comparison, formal decision specification | BLOCKED — not yet established |
| E3 datasets | Independent provenance + split manifests + genuine labeled traces | BLOCKED — fixture-only outputs |
| E4 baselines and ablations | Verified implementations and identical splits / adversarial budget | BLOCKED |
| E5 fault/attack evaluation | Raw trace-backed benign/attack outcomes, replay/false data/network stress | BLOCKED |
| E6 resource evaluation | End-to-end measured runtime scaling, not only communication formulas | BLOCKED |
| E7 statistical validation | Sample-size rationale, independent units, CIs/effect sizes, tests and multiple comparisons | IN PROGRESS — descriptive inference guardrail PR #pending |
| E8 reproduction | Documented environment and scripts verified by a second run | BLOCKED |
| E9 paper | Introduction/contributions/RQs/formal method/methodology/results/limitations, all numeric claims sourced | BLOCKED |

**Publication rule:** E2–E9 are mandatory for any claimed result/contribution in the manuscript. A reviewable PR, CI pass, figure, architecture diagram or mock CSV does **not** satisfy a research-efficacy gate.

## Next implementable tasks

1. Complete and verify draft hardware-bridge PR #74 on CI and isolated bench.
2. Correct descriptive FL reporting: never treat row count as a hypothesis test; ensure repeated rows/seeds cannot be presented as independent evidence.
3. Define the admission mechanism with a small formal executable policy and test explicit safety invariants without claiming field efficacy.
4. Implement canonical dataset loaders, integrity/split manifests and leakage checks; obtain licenses and actual traces legitimately.
5. Implement matched baseline comparison and raw-trace aggregation, then independent experiment campaigns, statistics and manuscript.

Owner should update the table using **MERGED/VERIFIED**, **IN PROGRESS**, **BLOCKED** or **NOT STARTED** only after confirming code and evidence. Avoid declaring submission readiness from this plan.
