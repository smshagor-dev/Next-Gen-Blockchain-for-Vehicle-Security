# TCP admission contention research status — 2026-11-22

Base main: e35f94e5968c401b405ae623986a080269055be5. AGENTS.md absent at repository root (404). Related draft PR #192 already covers connection-slot saturation; this experiment instead targets shared token-bucket admission concurrency and adversarial monotonic clock behavior.

| Workstream | Status | Evidence / remaining gate |
| --- | --- | --- |
| Global TCP admission budget contention | Implemented, unverified | 32 simultaneous claims, 7-token burst; run exact checkout |
| Idle refill / clock regression controls | Implemented, unverified | Three deterministic behavioral tests |
| Authenticated TCP framing / replay | Partial | Reconcile #180, #190, #191, #194 |
| Serial durable replay | Partial | Draft #194 |
| Atomic nonce/event inbox | Partial | Draft #197; production integration pending |
| Idempotent ledger append / independent finality | Blocked | Abstract model #199 is not production evidence |
| Physical local emergency stop | Blocked | No hardware access; remote actuation disabled |
| Authentic VeReMi NextGen and CAN evaluation | Blocked | Independent dataset provenance and frozen splits missing |
| Paired multi-seed incident-level baselines | Upcoming | Do not treat fixture CSV, 3-peer poisoning or microbenchmarks as main results |
| Original research article | Not ready | No defensible effectiveness or uncertainty estimates |

Reproduce: `python -m unittest discover -s tests -p 'test_tcp_admission_contention.py' -v`.
Full integration: `python -m unittest discover -s tests -v`.
Tests are committed but no exact-checkout pass is claimed. Clock and thread tests exercise the software admission boundary, not network throughput or malicious-node detection.

Next: execute on clean checkout, investigate any failures, then test shared budget under authenticated loopback TCP load with latency/CPU/RAM collection; reconcile overlapping ingress PRs before production merge.
