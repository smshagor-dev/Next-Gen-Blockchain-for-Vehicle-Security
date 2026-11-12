# Exploratory held-out CAM baseline protocol — VeReMi dataReplay

**Status:** executable CAM-level descriptive experiment, **not** an original V2X
incident-admission research result or submission-ready security paper.

## Question and traceability

What are the *descriptive* false-alarm and detection rates of deliberately
simple, untrained rules for the VeReMi NextGen v1.0.0 \`dataReplay\` CAM
message-level attacker labels on the **original publisher Test partition**?

Source release:
https://github.com/VeReMi-dataset/VeReMi-NextGen/releases/tag/v1.0.0
Documented message semantics:
https://github.com/VeReMi-dataset/VeReMi-NextGen/blob/main/Documentation/README.md

Pinned source asset: \`InTAS_highway_2_dataReplay.zip\`, expected SHA-256
\`08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea\`.
The dataset distribution licensing must be verified separately from the
generator repository's software license.

## Study boundaries

This is a **single-source, single-attack-category, auxiliary baseline**. It
does not create a novel detector. In particular, a CAM \`attacker=1\` label is
*not* evidence that an actual collision or road hazard occurred. No
incident-level label, signed enrolled identity, sensor-hardware attestation,
network incident quorum, vehicle actuation, or safety claim can be inferred.

Each source CAM appears separately in multiple receiver JSON logs. Count
**source transmission fingerprints** instead of receiver re-observations.
The conservative key is
\`(sender_id, sender_alias, messageID, sendTime_raw)\`. For duplicates, keep
the earliest receive timestamp; ties use lexicographic receiver path.
Inconsistent attacker labels for a matching key or appearance of a key across
train/validation/test is rejected; legitimate collision/aliasing and more
subtle scene/vehicle-level leakage are still possible. The method is not
certified physical-transmission deduplication.

## Method configuration, before held-out evaluation

- Original source-defined **Train/Validation/Test** path names preserved by
  the importer. Do not reshuffle CAM rows into random train/test sets.
- The Train partition is used for split-preservation evidence only; these
  rules have no supervised training.
- Only **Validation** negative-labeled distinct fingerprints define upper
  thresholds. At least 20 unique negative reference fingerprints required.
- Fixed one-sided nearest-rank **99th percentile**, strict \`>\` rule. No
  percentile search, model choice or threshold tuning using Test metrics.
- Feature 1: receive age = \`rcvTime - sendTime\` in exact source integer
  nanoseconds (negative values remain negative; not automatically anomalies).
- Feature 2: absolute sender-reported acceleration \`abs(acl)\` in m/s²,
  using the receiver log with earliest observed receive timestamp.
- Predefined methods: (B0) always-benign, (B1) receive-age threshold,
  (B2) acceleration-magnitude threshold, and (B3) fixed OR of B1/B2.
- Only source Test distinct fingerprints are scored. Report all methods,
  including zero positives, poor detection or increased false alarms.
- Outputs: TP/FP/TN/FN, positive/negative Test support, precision, recall,
  specificity, F1, false-positive rate, balanced accuracy. Undefined rates
  are JSON \`null\`, not fabricated zero.
- No significance test, no pseudoreplication of receiver rows or
  seed-count fiction. One source archive/test split cannot show generality.
  No tests are chosen based on observed results.

The CI workflow downloads only the official archive, verifies its exact
SHA-256, uses PR #82's nested-ZIP CAM importer and runs this evaluator.
Only small JSON/CSV result summaries and a source/result hash manifest are
uploaded as a CI artifact; raw publisher data stay transient on the runner.

## Reproduction

    python -m experiments.cam.heldout_replay_baselines \
      --source-csv /path/to/veremi_cam_messages.csv \
      --source-manifest /path/to/veremi_cam_manifest.json \
      --output-dir /path/to/heldout-evidence \
      --expected-archive-sha256 08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea

The CSV must have \`source_split\` values from original nested publisher
paths, unmodified CAM labels, per-receiver identity and source archive
hash binding; the source manifest must match exact normalized CSV bytes
and declared dataReplay source.

## Claim gates for original V2X paper

This auxiliary message-level detection baseline must **not** be substituted
for a test of the evidence-gated V2X incident admission mechanism (PR #80).
That requires independently generated, validated physical incident ground
truth, attacker control of enrolled identities, honest report missingness,
packet loss/partition and correlated source effects; matched published
comparators, held-out independent simulator scenarios, ablation, safe
availability, latency/resource budgets, and explicitly justified uncertainty.

Evidence and source limitations, including negative results, must appear
in the final paper. The claim flags from this utility stay
\`publication_ready=false\` and \`statistical_significance=false\`.
