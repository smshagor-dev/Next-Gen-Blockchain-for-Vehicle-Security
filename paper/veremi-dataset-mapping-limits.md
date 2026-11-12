# VeReMi NextGen: source label preservation and event-study limits

**Evidence status:** SHA-verified ingestion of two authentic publisher v1.0.0
archives has completed in [GitHub Actions run 43266683264](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43266683264).
This verifies data decoding and CAM label extraction, **not** security detection
performance, incident admission effectiveness or scientific originality.

## Verified archive provenance (2026-11-12)

| Publisher release asset | GitHub release SHA-256 | CAM receptions imported | attacker=1 | attacker=0 | unlabeled |
| --- | --- | ---: | ---: | ---: | ---: |
| `InTAS_highway_2.zip` | `31c756180fe8f86ca31bf3802f0a450f3beac49551d3eb23b25d8310a078fb4d` | 99,937 | 0 | Not used as inferential negative evidence | Missing labels are preserved |
| `InTAS_highway_2_dataReplay.zip` | `08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea` | 99,937 | 18,496 | 81,441 | 0 |

The publisher ZIP assets themselves were verified with `sha256sum -c` before import.
Both outer ZIP files contain nested Train, Test and Validation ZIPs, which
contain per-receiver JSON arrays. Each archive's original source split path is
preserved rather than inferring a partition from the archive name. Per-receiver
message repetitions are retained. Numeric strings and comma-separated planar
XYZ coordinates in the published files are parsed conservatively; raw timestamps
are stored as strings to avoid precision loss.

These values are **descriptive source/label counts**, not independent research
trials, incident labels, detection rates, false-positive rates, or effect sizes.
The original dataset's distribution license and study's incident-level mapping
still require independent review. No raw downloaded dataset is committed or
redistributed in this repository.

Source documentation: https://github.com/VeReMi-dataset/VeReMi-NextGen/blob/main/Documentation/README.md

Public dataset record: https://zenodo.org/records/19665762

Dataset reference (verify final publication metadata before manuscript use):
Hermann, A., Remmers, J.-N., Eisermann, D., Erb, B., and Kargl, F.
"VeReMi NextGen: A Dataset for Evaluating Misbehavior Detection Systems in
VANETs", IEEE Vehicular Networking Conference, 2026.

## Receiver-level duplication and split audit

The disk-backed `experiments/datasets/audit_cam_independence.py` audit ran on
both SHA-verified publisher archives in
[workflow 43267683137](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43267683137).

| Source metric | Baseline | dataReplay |
| --- | ---: | ---: |
| Receiver-level CAM records | 99,937 | 99,937 |
| Distinct sender/pseudonym/messageID/sendTime fingerprints | 45,101 | 45,101 |
| Repeated matching fingerprints in other receiver files | 54,836 | 54,836 |
| Cross-source-split matching fingerprints flagged | 0 | 0 |

The audit key is `sender_id + sender_alias + messageID + sendTime`, within a
single SHA-verified archive. It is **a matching-fingerprint heuristic**, not
proof of a distinct physical radio transmission, true vehicle identity or
statistically independent sample. No cross-split overlap was observed for
**this key in these two artifacts**; that does not prove no training/test
leakage under other identity mappings, feature selection or datasets.

| Publisher-defined source split | CAM rows | dataReplay attacker=1 | dataReplay attacker=0 |
| --- | ---: | ---: | ---: |
| Train | 37,701 | 6,541 | 31,160 |
| Validation | 17,977 | 3,212 | 14,765 |
| Test | 44,259 | 8,743 | 35,516 |

The matching baseline split rows have no `attacker` field and remain
**unlabeled**, not assumed benign. Reception counts and label balance are
source-data descriptions, not detector accuracy, generalized attacker
prevalence, or incident-admission outcomes. Raw trace and audit metadata
hashes are retained as CI artifacts; raw publisher data are not redistributed.

## Source interpretation

VeReMi NextGen contains per-receiver JSON arrays of Cooperative Awareness
Messages (CAMs). The documented field **attacker=1** means a significant
deviation or injected misbehavior in *this CAM*, not that an externally
observable collision/obstacle physically occurred. The same sender CAM
can appear in multiple receiver logs. The dataset includes sender aliases
(pseudonyms), but these are not by themselves authenticated, independently
enrolled physical-source identities.

**Do not map these labels directly to the evidence-gated V2X incident-level
ground_truth_incident field.** Such a conversion would invent event truth,
measurement independence and security assumptions not contained in the
original dataset.

Fields preserved by the importer: raw source send/receive time values,
sender_id, sender_alias, messageID, attacker, per-receiver file identity,
source planar XYZ, speed, acceleration, heading, declared split/subset,
and source archive SHA-256. This is not a projection to latitude/longitude,
a signed transport trace, or a new labeled incident dataset.

## Reproducible ingestion example

Download an official release artifact from the dataset's documented
GitHub/Zenodo distribution. Independently verify license/reuse terms for
the **data itself**; the generator repository's Apache-2.0 license must
not be assumed to be the distribution license.

Example archival release asset: InTAS_highway_2.zip from the publisher's
GitHub release v1.0.0, which lists expected SHA-256
`31c756180fe8f86ca31bf3802f0a450f3beac49551d3eb23b25d8310a078fb4d`.
Recheck this checksum against the publisher release before using it.

    python -m experiments.datasets.veremi_nextgen_import \
      --archive /path/to/InTAS_highway_2.zip \
      --output-dir /path/to/research/ve-remi-highway-2 \
      --expected-sha256 31c756180fe8f86ca31bf3802f0a450f3beac49551d3eb23b25d8310a078fb4d \
      --split unverified \
      --attack-subset baseline \
      --release-tag v1.0.0

The split and subset flags are **caller-declared** and cannot be verified
from the archive hash alone. The correct publisher dataset partition must be
selected and documented before empirical reporting; the above example is
illustrative and explicitly uses **unverified** partition metadata rather than asserting that the archive belongs to train/validation/test. The checksum verifies archive bytes, not the split label.

Output: `veremi_cam_messages.csv` and
`veremi_cam_manifest.json` (including raw ZIP and normalized CSV hashes).
No original archive data are committed to this project.

## Required additional study before original research conclusions

1. Verify a specific source release, its data license, digest, scenario,
   density, attack subset and publisher-designated train/val/test partition.
2. Convert CAM message/receiver/attacker records into an explicitly
   validated **message-level** misbehavior benchmark first; measure recall,
   precision and FPR on held-out CAMs using published methods.
3. Independently define what constitutes an actual *remote hazard incident*
   in simulator world truth, not using the attacker label as a substitute.
4. Ground receiver and sender planar coordinates using original simulator
   mapping before assessing 100-meter geospatial corroboration.
5. Establish independent enrolled physical identities across rotating
   pseudonyms and replicate authenticated session traces; do not treat
   multiple receivers of one CAM as independent corroboration.
6. Preregister incident labeling, attack injection, positive/negative
   exposure, partition handling, splits, baselines and uncertainty.
7. Compare the actual V2X admission policy and its ablations on matched
   incident traces; report safety/availability trade-offs and negatives.

The importer and synthetic unit tests establish data-handling semantics
only. All research efficacy and originality claims remain **not established**.
