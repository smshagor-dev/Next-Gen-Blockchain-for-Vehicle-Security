# Publication evidence audit — observed 2026-11-24

Run: https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45394942344
Head: df2ba7965c52420322486af6ced5ad4a569232ad
Executed merge revision in audit log: 35866d3bd85c34977ba360ea738de655d11e6667.
Candidate: 5a5e0851496f31e4afd626aeee218b0aeab66cb5.
Schedule: 93c5a6f03cac21076041767efbda58b5dfaf6ccd.

All five reported workflows succeeded at this PR head. The publication
audit job downloaded same-run held-out archives, validated 82 trials
and generated the CSV, SVG, PNG and audit JSON. This confirms internal
artifact verification by CI, not an independent security attestation or
a manual visual inspection of the figure.

Artifact: https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45394942344/artifacts/14920956398
CI-reported ZIP SHA256: 7f44fbab2f2a128a515473c6055a6861a41669b6fdab31c3a8e59873845eb445.

| Generated file | SHA-256 (CI-reported) |
|---|---|
| heldout-eligibility.csv | b0057b6b3e840452f8049adbf3c4f7869249e6a32d0e98d0df0cc5e901b9ac9e |
| heldout-eligibility.svg | 1d57d9c7142bf613cdc2af6cbe91e38f2d35e22ca929f848fceb3d6389daff4f |
| heldout-eligibility.png | 631edfb621c81400494e4debef5240e42cc8d5982cb3c1325a139b8a7bb7a796 |

Earlier first-run trace hashes differ because the current CI run executed
fresh processes and generated fresh observation scopes and timings. Do not
mix input bytes from different runs. Archive the complete selected run and
its exact source tree for DOI deposition.
