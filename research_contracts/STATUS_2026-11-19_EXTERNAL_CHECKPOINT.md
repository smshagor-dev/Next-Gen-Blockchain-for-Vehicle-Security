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


## 2026-11-19 exclusive-writer follow-up

| Workstream | State | Evidence / blocker |
| --- | --- | --- |
| Checkpoint issuer cross-process read-modify-write serialization | IMPLEMENTED / UNVERIFIED | POSIX nonblocking flock on persistent per-vehicle lock inode; protects load, compare, save and response |
| Contending issuer and unsupported-platform negative controls | AUTHORED / UNEXECUTED | Two regression tests; refused writer must not create checkpoint |
| Windows and non-cooperating writers | BLOCKED | Fail-closed on platforms without fcntl; advisory locks cannot stop writers ignoring the protocol |
| Atomic-write SIGKILL fault injection | UPCOMING | Pending-file recovery, replace/fsync crash points and durable revision replay controls remain untested |
| Go verified chain integration | UPCOMING | Issuer still trusts caller-supplied verified hash sequence |
| Authentic datasets and independent V2X experiments | BLOCKED | No publishable evidence or matched-baseline uncertainty estimates |
| Physical safety validation | BLOCKED | Local emergency control not demonstrated on hardware |

Commits: `0ba4ad3c` (POSIX exclusive writer), `9cfc5cc` (negative controls). Exact branch tests not executed. Run `python -m unittest discover -s tests -p 'test_independent_checkpoint_issuer.py' -v`. Next code task: deterministic SIGKILL around file fsync/replace, cleanup/recovery of stale .pending, then Go-chain integration. Do not merge or enable actuation.


## 2026-11-19: bounded checkpoint-history input (draft #154)
- **Implemented, not checkout-verified:** issuer now caps consumed history at 100,000 block hashes, rejects string/bytes and non-iterable input, and refuses over-limit iterators before durable state mutation. Commit cdd3cc1.
- **Authored negative controls:** infinite generator termination, exact-bound/over-bound behavior, and invalid sequence rejection in `tests/test_checkpoint_issuer_bounded_history.py`.
- **Test command:** `python -m unittest discover -s tests -p 'test_checkpoint_issuer_bounded_history.py' -v` (not executed on repository checkout).
- **Remaining:** iterator may block forever on a blocking next() and CPU cost remains linear up to the cap; issuer state is not protected against host filesystem rollback, nor is verified Go ledger integration established. No publication effectiveness evidence.

## 2026-11-19: opened-state inode trust boundary

| Workstream | Status | Evidence and limitation |
| --- | --- | --- |
| Issuer state inode owner/mode/link-count checks | IMPLEMENTED / UNVERIFIED | Commit e247bda: checks opened descriptor owner, private mode and single link before parsing |
| State permission/hardlink/restart negative controls | AUTHORED / UNEXECUTED | Commit 4d96579: three synthetic tests |
| Hostile parent-directory replacement and privileged compromise | BLOCKED | Directory custody and independent issuer key remain deployment assumptions |
| Physical emergency interlocks and authentic V2X efficacy | BLOCKED | No HIL, real incident labels or publishable experiments |

Run: `python -m unittest discover -s tests -p 'test_checkpoint_state_inode_metadata.py' -v`.
These checks are filesystem hardening, not finality or novel V2X efficacy evidence.
Next: execute exact branch suite and repair failures; prioritize receiver-side hardware interlocks and verified Go-chain ingress.
