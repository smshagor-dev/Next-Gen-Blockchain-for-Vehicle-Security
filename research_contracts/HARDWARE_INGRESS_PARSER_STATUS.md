# OmniGuard V2X research status — 2026-11-21

| Workstream | Status | Evidence / remaining gate |
|---|---|---|
| Pi ingress parser regression | Implemented; exact checkout unexecuted | Removed duplicated `try:` that prevented module parsing; AST regression added |
| Deferred serial verification quarantine | Implemented; exact checkout unexecuted | Generator consumption now within exception handler; regression tests added; overlaps draft #176, reconcile before merge |
| TCP authentication, nonce persistence, framing, connection caps | Partial | Existing main implementation; end-to-end socket adversarial tests and crash tests still needed |
| Arduino session budgets | Partial | Draft #175, not assumed merged |
| Serial sequence reference model | Partial | Draft #177, synthetic only |
| Independent local emergency control | Blocked | No physical validation; remote ECU command remains disabled |
| Ledger crash consistency and external finality | Partial / blocked | Local SQLite is not independent finality; fault injection pending |
| Evidence-gated V2X admission | Partial | Draft #171 is simulation-only; colluding enrolled peers remain |
| Authentic VeReMi NextGen / CAN provenance | Pending | Verify licenses, hashes, split policy and ground truth |
| Independent matched baselines, ablations, scaling, statistics | Pending | No publishable effectiveness numbers |
| Paper | Blocked | Await validated incident-level evidence and claim ledger |

## Reproduction

```sh
python -m unittest discover -s tests -p 'test_hardware_ingress_parser_quarantine.py' -v
python -m compileall -q hardware_bridge.py
python -m unittest discover -s tests -v
```

No exact-checkout test execution or hardware experiment is claimed for this change. Keep the PR draft; compare and reconcile with #176 before merge. Next: run parser and full suite, inspect serial read fault behavior and test malformed frames with a mocked transport, then test SIGKILL/restart nonce and ledger behavior.

## Mainline reconciliation (2026-11-24)
The serial generator quarantine implementation is already integrated through #176. Preserve current main's bridge, replay persistence and serial quotas; this PR retains the independent AST parser and quarantine regression controls. Exact-head CI remains required. No physical validation or effectiveness claim.
