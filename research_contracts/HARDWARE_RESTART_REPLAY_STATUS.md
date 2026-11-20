# OmniGuard V2X research status — restart replay checkpoint (2026-11-20)

| Workstream | Status | Evidence and limitations |
|---|---|---|
| Hardware HMAC ingress and bounded framing | Partial | Existing implementation; exact integrated runtime suite still pending |
| In-process nonce replay rejection | Partial | Existing verifier, regression negative control added; exact checkout execution pending |
| Replay protection across process restart | **Blocked / counterexample implemented** | New subprocess negative control demonstrates the testable failure condition; no durable receiver-side pin currently wired into hardware verifier |
| Remote actuation safety | Partial | Production bridge paths fail closed; independent physical emergency stop not hardware-tested |
| Ledger crash consistency and finality | Partial / blocked | SQLite and mocks do not demonstrate consensus finality or power-loss guarantees |
| Original evidence-gated V2X mechanism | Partial | Candidate and synthetic negative controls; independent effectiveness evaluation missing |
| VeReMi NextGen and CAN authentic data | Upcoming | Obtain provenance, licenses, labels and immutable raw hashes; fixture CSVs excluded |
| Matched attack baselines and ablations | Upcoming | Independent incident splits, enrolled colluders, spoofing, replay, faults, DoS |
| Runtime and statistical validation | Upcoming | Process/network CPU/RAM/latency, paired multi-seed uncertainty and effect sizes; n>=30 is not significance |
| Scientific manuscript | Blocked | No publishable effectiveness or physical safety evidence |

## Current isolated experiment

Run `python -m unittest discover -s tests -p 'test_hardware_restart_replay_control.py' -v` and `python -m research_contracts.hardware_restart_replay_control --output /tmp/hardware-restart-replay.json`, then full suite. This is a **non-actuating** counterexample with a valid enrolled key and fresh envelope: one process rejects the second identical envelope, but a new process has no prior nonce memory. This does not demonstrate a malicious-key compromise, nor that remote actuation occurs (the bridge disables it). The key and nonce are static research fixtures, never production credentials.

**Next code task:** Implement durable, atomic nonce claims with an independently trusted monotonic epoch and anti-rollback threat model, then test SIGKILL/restart, replay, expiry, concurrent sessions and cache saturation. Avoid treating SQLite as tamper-proof or blockchain finality. Do not merge without exact checkout tests and review.
