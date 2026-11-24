# Overlapping-writer SIGKILL research checkpoint (2026-11-19)

| Workstream | Status | Evidence and limitation |
| --- | --- | --- |
| Two independent OS-process SQLite writers | Implemented; local smoke verified | 3/3 standalone local surrogate trials passed; exact branch checkout not run |
| Precommit SIGKILL rollback with surviving writer | Implemented; local smoke verified | Victim exit -9, surviving writer committed one row; no physical power-loss test |
| Actual lock-wait overlap timing | Partial | Contender signals immediately before BEGIN IMMEDIATE; lock wait not independently observed |
| Production Go ledger receipt/finality | Blocked | SQLite surrogate cannot establish network consensus, signed finality or rollback resistance |
| Authenticated bounded hardware ingress and safe actuation | Partial/unverified | No hardware access or safety certification; local emergency control must remain independent |
| Genuine VeReMi NextGen/CAN provenance and incident labels | Partial | CAM attacker labels do not establish independent hazard incident truth |
| Matched multi-seed adversarial effectiveness and uncertainty | Upcoming | No publishable efficacy claims from fixture/smoke trials |
| Original research paper | Blocked | Requires independent incident truth, realistic matched baselines, network/resource data and validated uncertainty |

Run from repository root:

```bash
python -m unittest discover -s tests -p 'test_overlap_sigkill_control.py' -v
python -m research_contracts.overlap_sigkill_control --trials 10
```

This control is not a novel cryptographic mechanism, a real blockchain finality test, or publication-ready statistical evidence. No production actuator is invoked.
