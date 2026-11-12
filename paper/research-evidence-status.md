# Research evidence and implementation status (2026-11-12)

This ledger distinguishes engineering regression evidence from scientific research evidence. It is not a claim that any experiment is publication-ready.

| Area | Status | Evidence / limitation | Next action |
| --- | --- | --- | --- |
| Pi hardware trust boundary | PARTIAL (draft PR #74) | Signed framed Pi telemetry, replay cache, interlocked commands; Python regression step passed on CI run 43247996754. Hardware bench testing and complete CI still require confirmation. | Verify full PR #74 checks, review Arduino path and real hardware interlock. |
| Original V2X mechanism | NOT ESTABLISHED | Integrated security controls are not sufficient novelty. | Define distinct evidence-gated admission state machine, formal invariants, pre-registered RQs and strong comparable baselines. |
| Ledger crash consistency | OPEN | No verified crash/restart campaign in this ledger. | Implement fault-injection recovery tests, atomic persistence checks and durable replay protection. |
| Contract finality | LIMITED | Deterministic mock transaction hash is not blockchain consensus finality. | Distinguish mock receipts from confirmed finality; test real connector receipts if accessible. |
| FL descriptive statistics | PARTIAL (draft PR #77) | Removed invalid n>=30 significance claim, repaired Python syntax, added unique trial seed reporting, duplicate/non-finite guards and regression tests. Research Evidence Integrity CI run 43259147026 passed. | Review PR #77, preserve explicit no-inference status, then run actual independently sourced FL experiments. |
| Dataset provenance | OPEN | Fixture CSVs are not external real-world attack evidence. | Implement verified VeReMi NextGen / CAN ingest with hashes, licensing, schema checks and split provenance. |
| Adversarial V2X evaluation | OPEN | Four-row detector fixture and small sanity campaigns cannot support generalization. | Run matched baseline attack scenarios with independent seeds and held-out data. |
| Runtime scalability | OPEN | Analytical communication formula and 5-iteration microbenchmarks cannot establish fleet performance. | Capture end-to-end raw traces, resource metrics, network fault rates and p99 latency. |
| Statistical validation | TOOLING READY, EMPIRICAL EVIDENCE OPEN (draft PR #78) | Standalone paired comparison analyzer, 8 locally passing contract tests, exact/Monte Carlo sign-flip test, paired bootstrap CI, Holm adjustment and provenance hash; NO independently validated experimental runs. | Verify PR #78 CI, preregister hypotheses and independent runs, then evaluate actual datasets and baseline/ablation comparisons. |
| Manuscript | BLOCKED | Original novelty, datasets, baselines, and uncertainty not yet established. | Draft conclusions only after traceable raw evidence is available. |

## Evidence policy

1. Never promote synthetic fixtures, mocks, formula-only models, or CI tests to publishable empirical findings.
2. Report actual commands, versions, hashes, independent units, attack scenarios, baselines, and negative results.
3. Do not claim post-quantum security for classical ZKP/Pedersen layers or vehicle safety certification from software simulation.
4. Local emergency safety control must remain independent of blockchain or remote consensus availability.
