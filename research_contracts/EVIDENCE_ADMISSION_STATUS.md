# Evidence admission research matrix — 2026-11-21

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Authenticated bounded TCP ingest | Partial | Existing hardware transport code on main; full integration not revalidated in this change |
| Remote physical actuation isolation | Completed in current bridge code | Network ECU dispatch disabled; physical emergency-stop hardware not tested |
| Independent evidence gate | Implemented, isolated | Pure Python model, not wired to production ingress |
| Replay/spoof/false-data controls | Locally tested in isolated copy | Seven unittest methods; not authentic V2X incidents |
| Independent source corroboration | Partial | Distinct device IDs only; Sybil/enrollment collusion and source dependence not addressed |
| Formal safety property | Partial | 32 boolean configurations assert no physical command; not a formal proof of deployment |
| Crash recovery / external anchor | Partial / blocked | Existing draft PRs; no authenticated independent authority |
| Authentic VeReMi NextGen/CAN provenance | Pending | No dataset downloaded or validated |
| Matched baselines / ablations | Pending | No publishable effectiveness comparisons |
| Runtime network/CPU/RAM experiments | Pending | No measurements |
| Research manuscript | Blocked | Evidence insufficient |

## Hypotheses and threat model

H1: Under identical incident splits, independent corroboration reduces false admission by malicious *enrolled* senders compared with MAC-only admission, at a measurable false-quarantine cost. H2: local emergency precedence and a separate nonactuating evidence channel prevent any remote incident from authorizing physical actuation. H3: compromised independent corroborators degrade H1; source independence must be validated rather than inferred from device IDs.

Attacker: unauthenticated spoofers, replay senders, enrolled false-data senders, colluding enrolled identities, network flooders. Not modeled: physical ECU compromise, secure-element root, vehicle dynamics, genuine independent sensor trust.

Safety invariant in isolated model: for all decisions, physical_command_authorized == False. Admission is NOT an actuator command. This is a policy composition experiment, not a new cryptographic primitive or a certified safety mechanism.

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_evidence_gate.py' -v
```

Local isolated-copy result: 7 tests passed (2026-11-21); exact GitHub checkout and full suite not run. The fixed examples are non-publishable research outcomes. Next: verify on exact branch, wire decision only to ledger evidence intake (never to ECU), build provenance-checked incident loader and matched MAC-only/quorum/ablation comparisons.
