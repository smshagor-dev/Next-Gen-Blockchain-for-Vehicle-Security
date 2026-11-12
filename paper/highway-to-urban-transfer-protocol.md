# Frozen Highway-to-Urban VeReMi CAM transfer protocol

**Evidence class:** externally sourced CAM-message analysis, **not** an
original incident admission paper result, not preregistered confirmation,
not a true independently repeated experiment.

**Recorded before inspecting the new urban archive:** original VeReMi
NextGen v1.0.0 InTAS_urban_2_dataReplay.zip, SHA-256
9984cd0cfa32d31f607788a2a1c53c72970c6786563c785cce9b989bb7ce7777
(150,442,650 bytes, official GitHub release).
This urban scenario is geographically different from the previously
examined InTAS_highway_2_dataReplay.zip, pinned SHA-256
08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea.
Publisher: https://github.com/VeReMi-dataset/VeReMi-NextGen/releases/tag/v1.0.0

## Fixed evaluation policy, before examining urban outcome

The baselines and motion feature are inherited unchanged from draft PR #85.
The urban Test file is not used to define thresholds, class weights,
features, calibration quantiles, model selection or decisions.

1. Pin both publisher archive SHA-256 digests and importer-generated
   normalized CSV hashes; preserve original nested ZIP Train/Validation/Test
   source split. Reject missing CAM attacker labels.
2. Collapse duplicate receiver receptions on the four-value fingerprint
   (sender_id, sender_alias, messageID, sendTime), deterministically
   retaining earliest receiver observation. Reject label mismatch and
   identical fingerprint crossing source splits. This heuristic is not
   independent physical identity.
3. Score all five fixed methods without modification:
   always-benign, receive-age P99, absolute acceleration P99,
   their fixed OR, temporal motion residual P99.
4. Fit thresholds only on Highway_2 Validation negative-labelled
   distinct fingerprints, with one-sided nearest-rank 99th percentile and
   strict greater-than decision. Motion residual is the difference between
   displacement-derived planar speed and reported speed for consecutive CAMs
   from one sender/pseudonym within one source split. Gaps above five seconds
   and initial CAMs have no feature; these predict negative. Coverage reported.
5. Freeze thresholds before parsing urban CAM contents. Reject matching
   fingerprints between source and target archives rather than silently
   accept possible leakage.
6. Evaluate fixed rules only on Urban_2 Test CAM labels. No urban Train
   or Validation values or labels enter threshold selection. Report all
   TP, FP, TN, FN, precision, recall, specificity, F1, FPR, balanced
   accuracy, feature coverage and source hashes, including negative results.
7. Do not automatically declare statistical significance or publication
   readiness. A scenario is not an independent replicate.

## Why results remain exploratory

The temporal feature was conceived after inspecting Highway_2 Test
outcomes, and the Urban_2 source was chosen afterward. This is an external
source-scenario check, not formal preregistration, independent model
discovery confirmation, a published-baseline comparison or proof of original
novelty. The scenarios share simulation/generator ancestry and potentially
correlated assumptions. Pseudonym fingerprints cannot prove physical
transmission identity or absence of all temporal leakage.

VeReMi source attacker labels refer to message manipulation, not verified
collision or road-hazard incidents. This evaluation cannot establish the
evidence-gated incident admission effectiveness or physical safety of PR #80.

## Reproduction and evidence

    python -m experiments.cam.highway_to_urban_transfer \
      --highway-csv /verified/highway/veremi_cam_messages.csv \
      --highway-manifest /verified/highway/veremi_cam_manifest.json \
      --urban-csv /verified/urban/veremi_cam_messages.csv \
      --urban-manifest /verified/urban/veremi_cam_manifest.json \
      --output-dir /evidence/urban-transfer

GitHub Actions downloads and SHA-verifies source archives, uses original
publisher split labels, runs nine synthetic contract tests plus real external
data evaluation, and uploads only JSON/CSV reports and hash manifest.
No raw dataset redistribution.

**Publication gate:** original V2X paper requires independently verified
incident-world ground truth, corrupt/colluding enrolled identities, loss and
network partitions, published baselines, ablations, independently repeated
runs, statistical uncertainty and local emergency control isolation.
These are separate uncompleted tasks.
