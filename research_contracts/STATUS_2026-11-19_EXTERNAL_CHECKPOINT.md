# OmniGuard V2X research status — 2026-11-19 checkpoint control

| Workstream | State | Evidence / blocker |
| --- | --- | --- |
| Unauthenticated TCP ingestion, bounded framing, replay defense | PARTIAL / REQUIRES REAUDIT | No physical actuation; do not infer safe deployment |
| Local emergency stop independent of network | BLOCKED PHYSICAL VALIDATION | Hardware/HIL evidence unavailable |
| SQLite crash/restart fault controls | PARTIAL | Synthetic fault controls; not power-loss or distributed consensus |
| Go ledger cross-generation prefix pins | IMPLEMENTED, UNVERIFIED | Draft PR #154; pins vanish on restart |
| External checkpoint *verification* negative control | IMPLEMENTED, UNVERIFIED | PR #154: HMAC checkpoint binds vehicle, height, Go tip, external revision; 7 synthetic tests |
| Independent external anchor issuance / key custody / monotonic revision | BLOCKED | No trusted service, secure counter, or independent storage supplied; verifier alone is not finality |
| Evidence-gated incident admission and safety-isolated command authorization | PARTIAL | Threat-model and independent world-truth evaluation incomplete |
| Authentic VeReMi NextGen and CAN incident evaluation | PARTIAL / BLOCKED | CAM labels cannot serve as incident ground truth; real in-vehicle incident sources missing |
| Multi-seed independent network/runtime statistical campaign | UPCOMING | No publishable multi-seed measurements or effect-size intervals |
| Scientific manuscript and numerical claims ledger | BLOCKED | No publication-ready original-effectiveness evidence |

## Run evidence and limits

Commits: `830a42aa` (external checkpoint verification), `ee979271` (seven negative-control tests).
Tests authored, **not executed on the exact GitHub branch**: `python -m unittest discover -s tests -p 'test_go_external_checkpoint_control.py' -v`.
These controls test an authenticated external commitment *assuming* independently provisioned HMAC key and revision floor; they do not provide the independent anchor, protect against host/key compromise, or prove distributed finality.
Fixture CSVs, 3-peer poisoning checks, five-iteration microbenchmarks and offline communication formulas are NOT publication-ready main results.

## Next code task

Run the exact branch tests; fix failures. Then build a separate anchor-service test double with independent monotonic revision persistence and controlled crash/replay injection, followed by independent network nodes and authentic incident-grounded adversarial campaigns. Do not enable physical actuation or merge unverified changes.


## 2026-11-19 independent issuer simulation follow-up

| Workstream | State | Evidence / blocker |
| --- | --- | --- |
| Isolated checkpoint issuer, durable prefix and revision | IMPLEMENTED / UNVERIFIED | `independent_checkpoint_issuer.py`: fsync file, atomic replace, fsync directory; requires exclusive writer and independent custody |
| Restart, replay, truncation, rewritten prefix controls | AUTHORED / UNEXECUTED | Six synthetic unittest cases in `test_independent_checkpoint_issuer.py` |
| Authentic Go-ledger integration | UPCOMING | Caller must verify the entire Go hash/link chain *before* issuer receives tip sequence; issuer does not do this itself |
| Crash injection between fsync/replace and replay | UPCOMING | No SIGKILL interposition yet; stale .pending can block issuance until operator cleanup |
| Physical emergency-stop and TCP ingress safety | BLOCKED / REAUDIT | No deployment or hardware safety evidence |
| Research-grade V2X evaluation | BLOCKED | Authentic data, matched baselines and statistical campaign still outstanding |

Commits: `727650df` issuer, `3c3f26b8` tests. Exact GitHub checkout cannot be run in current execution container (GitHub DNS unavailable). No tests or numerical performance claims are reported as passing. The issuer is a **simulation-only trusted-service stand-in**, not secure monotonic storage, distributed consensus finality or a novel cryptographic primitive.

Run: `python -m unittest discover -s tests -p 'test_independent_checkpoint_issuer.py' -v`.

Next: verify exact branch tests; add exclusive-writer locking and fault injection around atomic persistence, then integrate with independently validated Go chain and compare rollback acceptance under identical fault traces.
