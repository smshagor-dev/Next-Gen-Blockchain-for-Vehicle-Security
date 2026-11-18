# Independent-process readiness fault status (2026-11-18)

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Exit-before-readiness fault injection | Implemented; checkout validation pending | Spawned child exits via os._exit(23) before publishing ready; parent polls exit state |
| Normal readiness control | Implemented; checkout validation pending | Spawned worker publishes readiness |
| Silent worker timeout | Implemented; checkout validation pending | Bounded timeout; child cleanup |
| Multi-writer SQLite surrogate | Partial | Draft PR #153, not blockchain finality |
| Durable inbox / ledger recovery | Partial | Draft PRs #150-#153, cross-store transaction remains unproven |
| Production authenticated ingress | Partial | Draft PR #148; unverified integration |
| Hardware interlocks / local emergency stop | Blocked | No physical hardware access or actuation tests |
| Authentic VeReMi NextGen / CAN provenance | Upcoming | No verified original dataset ingest in this change |
| Independent adversarial multi-seed study | Upcoming | No publishable effect sizes, CIs or latency data |

This experiment is a fault-detection control, not an effectiveness or safety result.
Do not treat synthetic fixtures, microbenchmarks, or SQLite surrogates as
publication-grade evidence. Do not merge until exact checkout tests pass.
Next: integrate early-exit detection into the process ledger campaign, then
SIGKILL during overlapping transactions and verified inclusion lookup.
