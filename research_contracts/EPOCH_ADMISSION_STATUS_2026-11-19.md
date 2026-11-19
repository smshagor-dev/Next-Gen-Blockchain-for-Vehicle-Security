# OmniGuard V2X research status — 2026-11-19 (epoch admission)

Related issues: #88, #92. Draft PR: #157. **Non-actuating synthetic protocol controls; not publication evidence.**

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Bounded epoch/nonce admission | Implemented, isolated validated | Seven isolated Python unit tests passed using equivalent source; exact GitHub checkout suite unexecuted |
| Monotonic epoch and stale/future rejection | Partial | Caller controls epoch advancement; no trusted clock or signed epoch authority |
| Local emergency stop latch | Partial | Simulation rejects remote admissions until explicit local reset; no physical safety interlock or HIL |
| Authentication and enrollment | Blocked | `verified` is an assumed caller assertion; no signature, credential revocation or Sybil defense |
| Colluding enrolled nodes | Counterexample known | Sender-count quorum admits two colluding enrolled claims |
| DoS resilience | Partial | Bounded buckets and nonces, but no per-connection framing, ingress authentication or CPU/network rate controls |
| Go ledger finality | Blocked | No independent durable consensus/finality proof |
| VeReMi NextGen and CAN provenance | Pending | No independently sourced, authenticated incident labels |
| Matched adversarial experiments | Pending | No real cohort, multi-seed independent comparison or publishable effectiveness estimates |
| Publication-ready paper | Blocked | Mechanism distinctiveness, prior-work comparison and independent experiments incomplete |

## Validation

Isolated `python -m unittest -v test_epoch_gate.py` returned **7/7 passed** for equivalent local code. Exact committed checkout test remains **unverified**; run:

```bash
python -m unittest discover -s tests -p 'test_epoch_admission_controls.py' -v
python -m unittest discover -s tests -v
```

## Scientific caveats

The local reset API accepts a Boolean supplied by its caller, not a secure operator-presence proof. This is **not** an actuation authorization mechanism. Epoch advancement clears pending state, including valid evidence, and therefore reduces availability. A fixed nonce budget eventually rejects all new admissions until a trusted epoch transition; this is an explicit fail-closed DoS trade-off. State is process-local and restart clears replay history. These properties need authenticated persistent replay protection and independently grounded traces before claims.

## Next code task

Audit actual hardware_bridge receiver on current main; implement authenticated, length-bounded, deadline-enforced framing and non-bypassable local stop before any physical command path. Then integrate epoch controls into identical-trace malicious enrolled-node and partition baselines. Keep draft; do not merge without exact-checkout validation.

## 2026-11-19 follow-up: replay-state and nonce-budget corrections

- **Implemented, exact-checkout unverified:** commit `825b320` makes repeated announcements of the *same* epoch idempotent, so they cannot erase the in-memory nonce history. A strictly newer epoch still clears history. Boolean epoch values are rejected (Python `bool` is an `int` subclass).
- **Implemented, exact-checkout unverified:** repeated observations from a sender already counted for the same incident/epoch/event no longer consume the global nonce budget. This closes a trivial enrolled-sender capacity-exhaustion path, but does not prevent a malicious enrolled sender from submitting many distinct incidents.
- **Tests committed, not executed:** `tests/test_epoch_replay_budget_regressions.py` covers same-epoch replay reset, 50 repeated-sender attempts, legitimate quorum under nonce pressure, capacity limits, boolean epoch rejection and transition to a new epoch.
- **Evidence classification:** implementation and test source committed; no exact-checkout test result, no independent adversarial effectiveness measurement, no hardware safety validation. These are not publishable main research findings.
- **Run locally:** `python -m unittest discover -s tests -p 'test_epoch_replay_budget_regressions.py' -v`; then `python -m unittest discover -s tests -v`.
- **Next:** audit actual hardware receiver on main, implement authenticated bounded TCP framing and physical safety interlocks; then compare enrolled-node capacity attacks under matched simulation traces.

## Follow-up: overlapping epoch replay retention

- **Implemented (unverified on exact checkout):** commit `d92aae8` retains nonce pins and corroboration buckets for epochs still inside the admission window. Previously `advance_epoch(1)` erased epoch-0 replay pins while `window=1` still accepted epoch-0 observations, permitting replay of the same verified observation. Epochs older than `epoch - window` are pruned to recover bounded capacity.
- **Regression source committed:** `dfd982f` adds four tests covering previous-epoch replay rejection, quorum continuity, expiry/capacity reclamation and idempotent epoch announcement.
- **Validation:** not executed against the GitHub branch (execution container cannot resolve github.com). Run `python -m unittest discover -s tests -p 'test_epoch_window_replay.py' -v` and full suite. No measured effectiveness or physical-safety result claimed.
- **Residual risk:** replay state remains volatile across process restart; a caller-provided verified flag is not authentication; accepting old epochs introduces an explicit freshness/availability trade-off. Priority remains authenticated bounded hardware receiver and non-bypassable local interlocks.
