# Research evidence status (2026-11-12)

This matrix tracks evidence, not publication claims. Statuses describe observed repository work and outstanding independent validation.

| Workstream | Status | Evidence and next gate |
| --- | --- | --- |
| Hardware TCP authentication, bounded framing, replay defense, actuation interlock | PARTIAL | Draft PR #74; main still has unauthenticated TCP and enabled-by-default hard stop. Review and validate PR #74 before merge. No real-vehicle authorization. |
| Ledger crash consistency and finality | PARTIAL — crash-checkpoint draft | New `experiments/ledger/crash_checkpoint.py` uses verified Go snapshots, bounded JSON, fsync temp, atomic replace and directory fsync; `tests/test_ledger_crash_checkpoint.py` injects process exits before/after rename. **Not wired to production Go ledger.** No distributed consensus finality, external rollback anchor or power-loss/HIL evidence. |
| Evidence-gated incident admission | PARTIAL | Draft PR #80 candidate; novelty and safety-availability benefits unproven. |
| VeReMi NextGen source importer | PARTIAL | Draft PR #82 validates archive format/provenance synthetically; authentic publisher data and license review outstanding. |
| Incident truth and split hygiene | PARTIAL | This branch adds structural split audit and tests. Manual provenance strings are self-asserted, not verified annotation. |
| CAN/in-vehicle authentic dataset | BLOCKED | No independently verified licensed data and mapping to safety-isolated incident truth yet. |
| Attack/fault baseline experiments | BLOCKED | No independently labeled real trials, matched splits, or measured independent repetitions. |
| Paired uncertainty and statistical inference | PARTIAL | Draft PR #78 provides exploratory paired analysis; no genuine results. PR #77 corrects n>=30 inference error. |
| Runtime scaling and network/CPU/RAM/latency | BLOCKED | No representative measured deployment runs or HIL access. |
| Research manuscript and numeric claim ledger | UPCOMING | Do not promote fixtures, 3-peer poisoning check, microbenchmarks, or offline communication formulas to main findings. |

## Structural audit usage

Run `python -m unittest -v tests.test_incident_split_audit` and `python experiments/v2x/audit_incident_splits.py independently_annotated_incidents.csv --output audit.json`.

Manifest columns: `source_id,incident_id,group_id,split,label,label_provenance`. Each incident is unique per source, and groups must not cross splits. Labels are binary incident truth assertions with declared annotation provenance, **not** CAM attacker labels. Passing this audit does **not** verify independence, source authenticity, license, annotation quality, temporal leakage, or research validity. All outputs explicitly say `publication_ready=false`.

Next: review hardware PR #74 and ensure safe local emergency control; validate authentic VeReMi source and license; independently annotate incidents and inspect temporal/session leakage before comparing candidate #80 against authenticated-only and corroboration baselines.

## Ledger checkpoint experiment boundary (draft)

The experimental local checkpoint verifies existing Go block hashes before writing, rejects append-history changes relative to the *currently available* checkpoint, and attempts crash-consistent replacement. Tests include actual POSIX subprocess `os._exit(73)` at three write stages, malformed/truncated files and generation mismatch. **A valid older checkpoint remains replayable after host rollback**; unkeyed SHA hashes can be recomputed over forged Go receipt metadata, demonstrating that this is not authenticated finality. Do not count these tests as independent distributed ledger or automotive experiments. The next code task is trusted external monotonic anchoring, Go server-side full-receipt signature/consensus receipt semantics, and independently measured power-failure recovery with representative storage. No physical lab access is assumed.
