# Original-publisher VeReMi dataReplay: observed CAM-level baseline results

**Artifact type:** transparent empirical data-processing and descriptive baseline
evidence from a single public dataset release; **not** an original V2X
incident-level result, an independently replicated experiment, or a basis for
submission readiness.

## Reproducible source and observed software run

- Publisher: https://github.com/VeReMi-dataset/VeReMi-NextGen/releases/tag/v1.0.0
- Source archive: \`InTAS_highway_2_dataReplay.zip\`
- Source SHA-256 checked before import:
  \`08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea\`.
- Original import and receiver-overlap confirmation:
  [PR #82](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/pull/82),
  [source audit CI 43267683137](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43267683137).
- Initial held-out B0–B3 comparison:
  [CI 43270036922](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43270036922).
- Follow-up B4 temporal consistency comparator:
  [CI 43270849074](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43270849074).
  Both regression and actual-source jobs passed in this run (11 synthetic
  contract tests plus source SHA-verified real data).

The output \`cam_heldout_results.json\`, \`cam_heldout_results.csv\`, and
\`cam_heldout_manifest.json\` are written by CI; raw source CAM records are
not committed or included in artifacts.

## Source participation and split hygiene

| Measure | Observed |
| --- | ---: |
| Receiver-level CAM records | 99,937 |
| Distinct sender+pseudonym+messageID+sendTime fingerprints | 45,101 |
| Duplicate matching receiver receptions excluded | 54,836 |
| Distinct Train fingerprints | 19,186 |
| Distinct Validation fingerprints | 7,023 |
| Distinct Test fingerprints | 18,892 |
| Test attacker=1 fingerprints | 3,280 |
| Test attacker=0 fingerprints | 15,612 |
| Test fingerprints with temporal motion feature | 18,221 |

This is *fingerprint-based* receiver deduplication. It does not prove unique
physical transmissions, independent vehicles, independent experiments, or
absence of scene/identity leakage. A fingerprint overlap across publisher
Train/Validation/Test partitions causes the evaluation to fail closed; that
guard did not fire for this pinned source archive.

## Source-held-out Test metrics

All entries use the same 18,892 deduplicated publisher Test fingerprints;
calibration thresholds come only from benign Validation fingerprints,
using the nearest-rank 99th percentile and strict greater-than decision.

| Method | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| B0 Always benign | 0 | 0 | 15,612 | 3,280 | undefined | 0.00% | 0.00% | 0.00% |
| B1 Receive age anomaly | 101 | 106 | 15,506 | 3,179 | 48.79% | 3.08% | 5.79% | 0.68% |
| B2 Absolute acceleration anomaly | 8 | 54 | 15,558 | 3,272 | 12.90% | 0.24% | 0.48% | 0.35% |
| B3 Age OR acceleration | 109 | 160 | 15,452 | 3,171 | 40.52% | 3.32% | 6.14% | 1.02% |
| B4 Temporal motion consistency | 489 | 135 | 15,477 | 2,791 | 78.37% | 14.91% | 25.05% | 0.86% |

**B4 is post-hoc and explicitly NOT confirmatory.** It was added after the
B0–B3 Test results from CI 43270036922 were inspected. Its apparent
improvement may reflect analysis-design choices made after seeing the same
test distribution. A new untouched traffic simulation/dataset, prespecified
analysis and independently measured robustness are needed to establish any
defensible superiority claim.

These are all **message-label** metrics. They are not false hazard
authorizations, missed emergencies, network attack success rates, or proof
of road-safety guarantees. All methods miss many attacker-labeled CAMs
(including B4, which misses 2,791/3,280 such Test fingerprints). The
first four simple baselines have extremely low recall; this negative result
must not be suppressed from a future methods comparison.

## Interpretation and research gaps

- VeReMi attacker=1 means source-labeled malicious/modified CAM
  attributes, **not** an independently verified road hazard incident.
- The source sender location/speed used by B4 are self-reported. A model
  reading these fields does not authenticate physical observations or prevent
  colluding enrolled participants from manufacturing consistent false alerts.
- No published SOTA misbehavior-detection comparison or independent
  confirmatory run is performed here.
- No per-seed variance, confidence interval, statistical significance,
  clinical/physical safety validation, or generalization claim is supported
  by one public source artifact.
- A genuine original-research paper about evidence-gated V2X admission
  requires independent incident-level truth, collaboration/collusion,
  held-out diverse scenarios, availability under partitions, realistic
  latency/resource tests, formal safety isolation, published baseline
  reimplementations and statistical analysis of independent runs.
- Source dataset distribution license/reuse terms must be confirmed
  independently before publication or redistribution.

**Claim flags remain:** \`publication_ready=false\` and
\`statistical_significance=false\`.
