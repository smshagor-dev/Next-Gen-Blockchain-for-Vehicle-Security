# Held-out results observed in CI

Workflow: https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45394351834

PR head: 6a4eba22efa053e21bbf5bc578434288768efac4. Both research jobs passed.
The consensus log reports checked-out merge revision d43b3c04b280eee1616996426821c0651d4ad524.
The logs report 82 successful trials across 41 fixed cells, zero errors and
reference disagreements. These are log-verified counts, not an independent
download/re-hash of the prior archives.

| Domain | Trials | Positive | Negative | Posture supported/unsupported eligible | Declared supported/unsupported eligible | Gate supported/unsupported eligible | Gate withheld | Gate not supported |
|---|---:|---:|---:|---|---|---|---:|---:|
| Consensus | 48 | 12 | 36 | 12/36 | 12/36 | 12/0 | 0 | 36 |
| Identity | 24 | 4 | 20 | 4/2 | 4/0 | 4/0 | 0 | 20 |
| PQC | 10 | 2 | 8 | 2/4 | 2/4 | 2/0 | 4 | 4 |

The paired counts in the method columns mean supported count / unsupported
count, not a ratio. The gate retained all supported trials and issued no
unsupported eligibility in this finite design. The PQC gate withheld four
unconfirmed sessions. No field prevalence, independent deployment sampling,
confidence interval or formal security guarantee is implied.

Reported trace SHA-256 values:
- Consensus: 0ba024c120634ccd9c549e542bd4e3e56d95fe9cb5eae45c3888e2d000b9583a
- Identity: 496aabb8aec83ff75791cb1b3a4b6fae4eace58cc907ae01b6551ed8a09dd992
- PQC: 8b7eefbe94c25cbd8e29d6e4836cb86d472b381919bf2d26404d1f8edc0347eb

Artifact archive links:
- https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45394351834/artifacts/14919758625
- https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45394351834/artifacts/14919614043

Publication audit code is added for subsequent same-run artifact download,
trace digest verification, frozen candidate and schedule validation, trial
allocation and reference checks, independent aggregate recalculation and
plot generation. It does not authenticate the observation origin. The new
audit execution is pending; no figure file is claimed to have been rendered yet.
