# v2.8 Runtime Security Detection & Software-HIL Validation

## Scope

v2.8 adds bounded runtime security-event correlation and deterministic software-HIL validation on top of the v2.1-v2.7 hardening work.

This phase is designed to answer two questions:

1. Can security failures already rejected by the hardened protocols be correlated into a useful runtime incident state without retaining secrets or raw packet bodies?
2. Can the resulting containment/safe-mode decision policy be validated reproducibly without touching real vehicle hardware?

## Runtime security monitor

`runtime_security_monitor.py` provides `RuntimeSecurityMonitor` with:

- a bounded in-memory event buffer;
- normalized reason codes only;
- one-way subject tokens instead of raw vehicle/node identifiers;
- no packet bodies, credentials, keys, tokens, or arbitrary exception text;
- SHA3-256 hash chaining across retained evidence records;
- a rolling correlation window;
- severity-based incident scoring;
- explicit incident levels: `NORMAL`, `WATCH`, `CONTAIN`, `CRITICAL`;
- explicit recommended actions: `NONE`, `AUDIT_ONLY`, `ISOLATE_NETWORK`, `SAFE_MODE_REQUEST`.

When the bounded buffer is full, the oldest record becomes the evidence anchor and is removed. New records remain verifiable relative to that anchor. This prevents unbounded memory growth, but it is not durable forensic storage.

## Safety decision boundary

Network/authentication/consensus attacks may escalate to `ISOLATE_NETWORK` without commanding a vehicle stop.

A `SAFE_MODE_REQUEST` is reserved for safety-critical security categories such as:

- ledger-integrity compromise;
- authenticated-service authenticity failure/spoof indication;
- telemetry-integrity compromise;
- actuator-integrity compromise.

The runtime monitor does **not** directly operate CAN, serial, brakes, throttle, or ignition. It produces a decision. Actuation remains a separate safety-control responsibility.

## Runtime hooks

### Sync network

The v2.8 `SyncServer` records normalized events for:

- rejected permissioned-consensus votes;
- validator/vehicle identity mismatch;
- unauthorized validators;
- unregistered vehicle admission;
- missing enrollment registry;
- rejected handshakes;
- unauthenticated vote channels.

The sync server exposes value-free runtime-security metadata through `runtime_security_metadata()`.

### Local Go control-backend adapter

`runtime_backend_patch.py` records normalized control-plane events for:

- HTTP 401/403 authentication rejection;
- HTTP 409 replay/conflict rejection;
- backend connection unavailability;
- backend process exit before authenticated health verification;
- ledger snapshot integrity failure detected during refresh.

The adapter does not store response bodies or exception strings in the runtime evidence buffer.

## Deterministic software-HIL validation

`hil_security_validation.py` is a repository-local simulation harness. It does not open CAN, serial, or external network interfaces.

The default scenarios are:

1. **clean baseline** — no event means no containment and no stop request;
2. **replay burst** — repeated replay activity isolates network trust but does not request a stop;
3. **cross-layer auth attack** — sync MAC plus consensus-signature failures correlate to containment;
4. **ledger tamper** — requests safe mode exactly once;
5. **authenticated-service spoof indication** — requests safe mode exactly once;
6. **sensor/telemetry integrity attack** — requests safe mode exactly once.

The report records whether each scenario passed, the final incident level/action, whether network isolation was requested, whether safe mode was requested, the simulated stop-command count, and evidence-chain validity.

## CI validation

The Security Baseline workflow now:

- compiles the runtime monitor and HIL harness;
- runs runtime-monitor unit tests;
- runs sync/backend runtime-hook tests;
- runs software-HIL scenario tests;
- executes the deterministic HIL report generator;
- retains the HIL JSON report as a workflow artifact;
- continues all prior security regression, adversarial, Go fuzz, and Go build gates.

## Security claims intentionally not made

v2.8 does **not** claim:

- production IDS/IPS certification;
- formal detection-rate guarantees;
- ASIL or ISO 26262 safety certification;
- real CAN-bus fault injection coverage;
- real ECU timing/actuation validation;
- fleet-scale DDoS resistance;
- tamper-proof durable forensic storage;
- protection against a privileged same-process attacker able to modify monitor memory;
- exhaustive HIL state-space coverage.

The evidence chain is useful for detecting accidental or unprivileged in-memory record mutation inside the retained window. Durable forensic evidence requires a later append-only signed/remote or hardware-backed evidence store.

## Follow-up

A subsequent incident-response phase should add durable append-only evidence export, alert acknowledgement/state transitions, operator playbooks, recovery gates, and hardware/bench HIL execution with explicit safety interlocks.
