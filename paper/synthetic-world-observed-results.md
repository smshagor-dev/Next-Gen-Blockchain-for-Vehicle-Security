# Observed stochastic incident-world trial results (software only)

**Date:** 2026-11-13. **Status:** EXPLORATORY_SYNTHETIC_ONLY; **not submission-ready independent external evidence**.

GitHub Actions execution: [Stochastic Incident World Research run 43488166573](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43488166573). The Python regression tests, frozen simulation, provenance/artifact upload and claim-boundary assertions passed.

## Design

- 64 distinct pseudorandom seeds, seven fixed scenarios, 16 incident
  opportunities per scenario and seed: **7,168 world opportunities per policy**.
- Authentic-source labels / physical truth: **NOT PROVIDED**. The separate
  world CSV uses a model-derived, synthetic oracle; the delivered packets CSV
  excludes truth labels. Session-authentication is an assumed gate precondition.
- 9,984 simulated delivered reports; three identical-policy-replay input traces.
- The 21,504 policy/incident decisions are compared under an identical frozen
  stochastic source model. All positive zero-packet opportunities are counted
  as false negatives, not excluded from the denominator.

## Incidents counted against synthetic world truth

| Network admission policy | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| Authenticated identity only, relay first | 1,517 | 2,048 | 2,579 | 1,024 |
| Original first-reference quorum 2 | 977 | 1,024 | 3,119 | 2,048 |
| Research consistent-subset quorum 2 | 1,967 | 1,024 | 2,129 | 2,048 |

A true opportunity whose forwarded report describes a location >100 m from
the independent synthetic world position is counted as **FN**, not TP, even
when the network relayed an assertion. Thus 1,024 first-writer poisoned
auth-only cases were **mislocated relays**, not successful real-hazard notices.

### Controlled first-writer scenario

Of the 1,024 true, intentionally poisoned-first trials, the
anchor-reference policy returned **0 correctly located relays** and
consistent-subset policy returned **990** (34 missed). Paired seed bootstrap:
subset minus anchor = **0.9668**, exploratory 95% interval **[0.9570, 0.9766]**.
This is conditional on the authored attacker offset, packet-drop model,
three honest reporters, 100-m threshold, bounded report pool and chosen
simulator. It is **not** a confidence interval for field deployments or
independent confirmatory evidence of a novel algorithm.

### Important negative results

- The two matching enrolled malicious identities' 1,024 fabricated incidents
  passed **both quorum-2 policies**: false-positive rate 100% in that authored
  collusion case. Quorum is **not** trusted sensor truth.
- All 1,024 true zero-report opportunities were missed by every policy.
- All 1,024 true partition opportunities were missed by both quorum policies.
  Authenticated-only relayed 495 of 1,024, without checking corroboration.
- The 1,024 false single-reporter events were rejected by both quorum policies
  but relayed by authenticated-only.
- All 1,024 false zero-capture opportunities were TN for all methods.

## Audit

The CI artifact \`stochastic-v2x-synthetic-world-only\` contains
\`world.csv\`, \`deliveries.csv\`, \`decisions.csv\`, \`summary.json\` and
\`manifest.json\`, and source/output SHA-256 digests. These were downloaded
and independently rechecked in the research working environment:

- all four output SHA-256 digests matched;
- world=7,168, deliveries=9,984, policy rows=21,504;
- per-policy TP/FP/FN/TN were recomputed directly from decision CSV rows;
- the delivery CSV has no \`world_hazard\` column.

This is **file integrity and model-output accounting**, not independent
validation of sensor origin, captured radio sessions, physical harm prevention,
power-loss safety or real-world event labels.

## Required next evidence

1. External SUMO / traffic scenario world-event exports, independent of this
   scenario generator, with external source SHA-256 and incident adjudication.
2. Paired authenticated hub captures and complete capture interval witnesses.
3. Realistic radio delay/drop and independent scenario variants; published
   comparator implementations and separate untouched confirmatory evaluation.
4. Fully instrumented, independent dummy-load physical bench safety trials
   as defined in \`paper/physical-hil-safety-evidence-protocol.md\`.
5. A non-post-hoc novelty comparison and reproducibility package.

**Publication claim flags:** \`publication_ready=false\`,
\`physical_hardware_validated=false\`,
\`independent_external_incident_labels=false\`.
