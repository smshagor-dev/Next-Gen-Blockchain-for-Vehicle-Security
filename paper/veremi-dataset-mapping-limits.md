# VeReMi NextGen: source label preservation and event-study limits

**Evidence status:** importer implementation, not a completed dataset evaluation.

Source documentation: https://github.com/VeReMi-dataset/VeReMi-NextGen/blob/main/Documentation/README.md

Public dataset record: https://zenodo.org/records/19665762

Dataset reference (verify final publication metadata before manuscript use):
Hermann, A., Remmers, J.-N., Eisermann, D., Erb, B., and Kargl, F.
"VeReMi NextGen: A Dataset for Evaluating Misbehavior Detection Systems in
VANETs", IEEE Vehicular Networking Conference, 2026.

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
\`31c756180fe8f86ca31bf3802f0a450f3beac49551d3eb23b25d8310a078fb4d\`.
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

Output: \`veremi_cam_messages.csv\` and
\`veremi_cam_manifest.json\` (including raw ZIP and normalized CSV hashes).
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
