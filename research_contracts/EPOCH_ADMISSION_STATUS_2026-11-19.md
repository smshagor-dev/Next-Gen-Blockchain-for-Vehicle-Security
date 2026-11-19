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
