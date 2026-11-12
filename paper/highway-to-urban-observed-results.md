# Real publisher Urban_2 CAM transfer: observed exploratory results

Date: 2026-11-12. **This records measured data-processing results, not original
incident-level V2X scientific conclusions or publication-ready evidence.**

## Immutable source identity and verification

Publisher release:
https://github.com/VeReMi-dataset/VeReMi-NextGen/releases/tag/v1.0.0

- Original calibration source: InTAS_highway_2_dataReplay.zip
  (SHA-256 08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea).
- Different target scenario: InTAS_urban_2_dataReplay.zip
  (SHA-256 9984cd0cfa32d31f607788a2a1c53c72970c6786563c785cce9b989bb7ce7777).
- [GitHub Actions run 43274403228](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43274403228) SUCCESS:
  both actual publisher ZIP checksums verified; both ZIPs decoded;
  SHA-bound source manifests validated; all 9 synthetic transfer contract
  tests passed; full real target Test evaluation completed.
- Run artifact: veremi-highway-to-urban-cam-transfer-evidence (artifact ID
  13969084219, JSON/CSV results and SHA manifest only). Raw publisher data
  were not committed or uploaded as an artifact.

## Source calibration lock

All methods and thresholds were locked using **Highway_2 Validation benign
distinct fingerprints only**. No Urban_2 feature/label was used to fit
thresholds or choose the temporal motion comparator.

| Pre-fixed threshold / policy | Observed value |
| --- | ---: |
| Negative Highway Validation fingerprints for calibration | 5,756 |
| Temporal-feature eligible negative Highway Validation | 5,599 |
| Upper quantile (nearest rank; strict greater-than) | 0.99 |
| Source receive-age upper threshold | 1,942,244 nanoseconds |
| Source absolute acceleration upper threshold | 4.5 m/s² |
| Source temporal motion residual upper threshold | 1.3672399337276424 m/s |
| Motion time-gap upper limit | 5 seconds |

The temporal feature was invented after the earlier Highway_2 Test output
was inspected; it is **post-hoc exploratory**. Urban_2 was selected before
*its* outcomes were observed but after Highway_2 outcomes were known. Thus
this is an external-scenario check, **not preregistered confirmation**.

## Real target CAM counts and source split hygiene

| Original Urban_2 dataReplay quantity | Count |
| --- | ---: |
| Per-receiver CAM records imported | 812,795 |
| Matching fingerprints repeated across receivers | 566,713 |
| Distinct sender+pseudonym+messageID+sendTime fingerprints | 246,082 |
| Distinct Train fingerprints | 102,782 |
| Distinct Validation fingerprints | 29,521 |
| Distinct Test fingerprints | 113,779 |
| Test attacker=1 labels | 20,189 |
| Test attacker=0 labels | 93,590 |
| Test fingerprints with valid temporal motion feature | 112,311 |
| Exact-key source/target matching fingerprints | 0 |

These are **CAM fingerprint counts, not independently repeated trials,
independent physical vehicles, or incident-level ground truth**. Zero
exact-key intersections does not rule out correlated simulator dynamics or
scene/identity-level leakage across source scenarios.

## Fixed-method Urban_2 Test results

All rows use the **same 113,779 distinct target Test fingerprints** with
20,189 attacker=1 and 93,590 attacker=0 labels. Thresholds come exclusively
from the original Highway_2 Validation subset, not Urban_2.

| CAM-level method | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Always benign | 0 | 0 | 93,590 | 20,189 | Undefined | 0.00% | 0.00% | 0.00% |
| Receive age P99 | 195 | 702 | 92,888 | 19,994 | 21.74% | 0.97% | 1.85% | 0.75% |
| Absolute acceleration P99 | 59 | 220 | 93,370 | 20,130 | 21.15% | 0.29% | 0.58% | 0.24% |
| Age OR acceleration P99 | 254 | 918 | 92,672 | 19,935 | 21.67% | 1.26% | 2.38% | 0.98% |
| Temporal motion residual P99 | 3,076 | 340 | 93,250 | 17,113 | 90.05% | 15.24% | 26.06% | 0.36% |

Results are transcribed from the completed SHA-bound CI output. See the
machine-readable workflow artifact for all full-precision values and
hashes; reported percentages are rounded for display.

The last comparator still misses **17,113/20,189** attacker-labelled
target CAM fingerprints. Low FPR does NOT imply strong safety detection
or remote incident authorization, and these metrics cannot be generalized
to physical collisions, ECU commands or adversarial enrolled cohorts.

## Claim ledger and remaining blockers

- **Directly verified:** official archive digest match, parsing, deduplicated
  CAM split counts, frozen threshold configuration, held-out CAM confusion
  matrices and source/result hash generation; 9/9 regression tests passed.
- **Exploratory only:** transfer of sender-reported simple temporal motion
  features between two related generator scenarios, both from one source
  dataset family. Prior work on kinematic consistency exists; this method
  is not an original cryptographic or V2X admission contribution.
- **Not verified:** independent simulation seeds, causal incident-level
  labels, physical vehicle identity and hardware measurement validity,
  source dataset redistribution license, SOTA baselines, independent-trial
  uncertainty, statistical significance, adversarial collusion, severe
  network faults, emergency safety and actual physical actuation interlocks.
- **Original research status:** insufficient to conclude a novel V2X
  admission mechanism or produce a submission-ready research paper.

All generated result documents explicitly set publication_ready=false,
confirmatory_study=false and statistical_significance=false.
