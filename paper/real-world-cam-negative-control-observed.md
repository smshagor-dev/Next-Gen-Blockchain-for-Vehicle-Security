# Independent real-world CAM negative-control audit — observed data, no incident inference

**Execution date:** 2026-11-14.
**Evidence source:** Zenodo DOI [10.5281/zenodo.21644263](https://zenodo.org/records/21644263).
The publisher describes an approximately 15-minute real-world multi-sensor
V2X recording with no physical collision. The archive exposes 2 vehicles
transmitting CAMs and one bicycle transmitting VAMs, but this audit uses only
the publisher's \`cam.csv\` (not the other modalities).

## Reproducible source-backed execution

[Real External Negative Control CI run #43542991506](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43542991506):
parser regression tests, publisher download, original digest verification,
strict CSV processing, metadata report, and no-claims guard all passed.

| Source property | Observed |
| --- | --- |
| Publisher CAM CSV MD5 | \`8e4e0dfde05fa46b4f66bf92efbbe70f\` |
| Independently computed SHA-256 | \`1e503fa81df53efaf45213951e9daf79d87cc8570ff6bc5e9477dd4552900305\` |
| Downloaded source bytes | 15,608,736 |
| CAM rows | 9,098 |
| CSV columns | 58 |
| Distinct self-reported \`stationId\` values | 2 |
| Distinct \`receiverID\` values | 1 |
| \`collisionWarningEngaged\` cell values | MISSING in all 9,098 rows |
| \`emergencyBrakeEngaged\` cell values | MISSING in all 9,098 rows |

The publisher's MD5 confirms the exact expected file under the publisher's
listed digest. The local SHA-256 supports byte-level pinning for future audits.
Neither checksum proves a physical event label, an enrolled certificate
identity, session-MAC verification or actual collision absence independently
of the publisher's assertion.

## Scientific claim boundary

There are **no empirically labeled positive hazard incidents or even
explicitly enumerated independently reviewed negative hazard opportunities**
in the CAM file. No warning-engagement values are present. The aggregate
statement "no collision was recorded" is not a per-message or per-incident
label. Treating 9,098 individual CAM messages as 9,098 independent negative
incidents would fabricate a denominator and falsely imply a false-positive
rate. Two station IDs do not prove two independent authenticated devices, or
two independent witnessed hazard reports.

This source does **not** validate the OmniGuard V2X EvidenceAdmissionGate
or the ConsistentSubsetAdmissionGate. It provides authentic external
source-ingestion and dataset-provenance evidence only, not new efficacy
metrics. It is independent of the earlier VeReMi NextGen CAM replay archive
but does not solve the independent incident-labeling gap.

**Flags:** \`publication_ready=false\`,
\`v2x_incident_accuracy_measurable=false\`,
\`physical_hil_validated=false\`.

## Further work requiring external inputs

- Separately adjudicated positive/negative traffic-event opportunities,
  ideally collision outputs from a publisher simulator accompanied by
  synchronized source trajectories and time/position.
- Captured enrolled sender sessions or verifiable simulator-radio messages,
  not station ID strings or self-reported sensor hashes.
- Matched raw network traces for both candidate and published baselines.
- Independent instrumented physical emergency-stop measurements on an
  isolated dummy-load research bench.

All numerical claims above are file-descriptive, not independent hazard
admission results.
