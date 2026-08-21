# v2.9 Incident Response, Tamper-Evident Evidence & Recovery Gates

## Scope

v2.9 turns the v2.8 runtime-security decision stream into an explicit incident-response state machine.

The goal is not automatic remediation. The goal is to make containment/recovery decisions auditable, replay-resistant, operator-authorized, and fail-closed while preserving the existing safety boundary: the security layer does not directly release brakes, ignition cut, CAN/serial interlocks, or other vehicle actuators.

## What is added

### 1. Persisted tamper-evident incident journal

`incident_response.py` provides `IncidentEvidenceJournal`.

Each JSONL transition contains only normalized incident metadata:

- monotonically increasing sequence number;
- incident ID;
- incident state;
- strongest requested action;
- highest incident level;
- safety-critical flag;
- recovery-health progress;
- runtime-monitor evidence anchor/tail hashes;
- runtime-monitor event count;
- normalized recent source/category names;
- previous incident-journal entry hash;
- SHA3-256 entry hash;
- HMAC-SHA256 signature from `SMARTCAR_INCIDENT_EVIDENCE_KEY`.

Journal writes use append mode, `fsync()` per entry, and `0600` permissions where supported. The configured evidence directory is created with restrictive permissions where supported. Symlinked journal targets and filename path traversal are rejected.

The journal is **tamper-evident, not tamper-proof**. A privileged attacker able to modify both the journal and its signing key can rewrite valid history. WORM storage, remote transparency logs, TPM/HSM-backed signatures, and remote attestation remain future work.

### 2. Separate operator authorization domain

`SMARTCAR_INCIDENT_OPERATOR_KEY` is independent from the evidence-signing key and every other credential domain.

Operator actions are HMAC authenticated over:

- protocol version;
- action (`ACKNOWLEDGE` or `RECOVER`);
- incident ID;
- UTC timestamp;
- random nonce.

Authorization is rejected when:

- the signature is invalid;
- the action does not match the requested transition;
- the incident ID does not match;
- the timestamp is stale/future outside the configured window;
- the nonce is malformed;
- the nonce was already used;
- the bounded nonce cache is saturated.

The evidence and operator keys are registered as separate domains in `credential_policy.py`, so exact key reuse is rejected by the central credential policy.

### 3. Latched incident state

The v2.8 rolling runtime decision can age back to `NORMAL` after its correlation window expires. v2.9 intentionally separates that transient decision from the incident lifecycle.

`IncidentResponseManager` uses the states:

1. `CLEAR`
2. `OPEN`
3. `ACKNOWLEDGED`
4. `RECOVERY_PENDING`
5. `RECOVERED`

A runtime event that reaches `ISOLATE_NETWORK`, `SAFE_MODE_REQUEST`, `CONTAIN`, or `CRITICAL` opens an incident.

New containment evidence while an incident is acknowledged:

- keeps the same incident ID;
- resets healthy progress;
- invalidates the old acknowledgement;
- returns the incident to `OPEN`.

Therefore a short rolling detection window cannot silently clear an incident.

### 4. Explicit recovery gate

Recovery is never automatic.

A recovery transition requires all of the following:

1. the incident was explicitly acknowledged with a valid signed operator action;
2. the runtime evidence chain is valid;
3. the current runtime decision is exactly `NORMAL` / `NONE`;
4. the configured number of consecutive healthy evaluations has completed;
5. a fresh signed `RECOVER` authorization is supplied;
6. if the incident was safety-critical, an external safety-interlock confirmation is explicitly supplied.

The default healthy-observation requirement is 3.

A `WATCH` / `AUDIT_ONLY` decision is not considered healthy enough for recovery.

### 5. Runtime decision decay without evidence deletion

`RuntimeSecurityMonitor.snapshot()` now refreshes the rolling decision using the current correlation window.

This means old events can stop contributing to the transient score while the retained evidence chain remains present and verifiable. The incident manager remains latched separately until the explicit recovery workflow completes.

## Runtime construction

`incident_response_runtime.py` provides an explicit same-process factory:

```python
from incident_response_runtime import create_runtime_incident_response_manager

manager = create_runtime_incident_response_manager()
manager.evaluate()
```

Importing the factory does not open a journal or require credentials. Construction is explicit so a process that does not own the runtime monitor cannot accidentally claim to manage its incidents.

## Operator playbook

### Network-only containment

Example: replay burst or unauthorized validator activity.

1. Observe `ISOLATE_NETWORK` / `CONTAIN`.
2. Keep the network trust boundary isolated.
3. Preserve the signed incident journal.
4. Investigate and remove the cause.
5. Submit signed `ACKNOWLEDGE` for the active incident.
6. Wait for the required consecutive `NORMAL/NONE` evaluations.
7. Submit a new signed `RECOVER` action.
8. Only then may a separate network-control component restore trust/connectivity.

No vehicle safe-mode release is implied by a network-only recovery.

### Safety-critical containment

Example: ledger integrity failure, authenticated-service spoof indication, telemetry-integrity failure, or actuator-integrity failure.

1. Treat `SAFE_MODE_REQUEST` as a safety-control request, not as proof that physical actuation occurred.
2. Preserve the incident journal and the underlying runtime evidence chain.
3. Keep external safety controls/interlocks engaged according to the bench/vehicle safety procedure.
4. Investigate the root cause and repair the affected component.
5. Submit signed `ACKNOWLEDGE`.
6. Complete the configured healthy observation window.
7. Independently verify the physical/bench safety interlock state.
8. Submit signed `RECOVER` with explicit safety-interlock confirmation.
9. A separate safety controller may then decide whether releasing safe mode is allowed.

v2.9 does not issue the physical release command.

## Configuration

Required independent credentials:

```text
SMARTCAR_INCIDENT_EVIDENCE_KEY=
SMARTCAR_INCIDENT_OPERATOR_KEY=
```

Journal policy:

```text
SMARTCAR_INCIDENT_EVIDENCE_DIR=logs/security
SMARTCAR_INCIDENT_EVIDENCE_FILENAME=incident-evidence.jsonl
SMARTCAR_INCIDENT_EVIDENCE_MAX_BYTES=67108864
SMARTCAR_INCIDENT_EVIDENCE_MAX_RECORD_BYTES=16384
```

Operator/recovery policy:

```text
SMARTCAR_INCIDENT_OPERATOR_AUTH_WINDOW_SEC=120
SMARTCAR_INCIDENT_OPERATOR_NONCE_CACHE_ENTRIES=1024
SMARTCAR_INCIDENT_RECOVERY_HEALTHY_OBSERVATIONS=3
```

## Deterministic validation

`incident_response_validation.py` runs repository-local scenarios without external hardware or network access:

1. network-only incident acknowledgement and recovery;
2. safety-critical incident blocked until external interlock confirmation;
3. forged operator action rejection;
4. persisted journal tamper rejection on reopen;
5. new containment evidence invalidates the previous acknowledgement.

The CI workflow stores `security-reports/incident-response-validation.json` as an artifact.

Unit tests additionally cover:

- raw subject/secret redaction;
- journal reopen verification;
- operator nonce replay rejection;
- healthy-window gating;
- safety-critical versus network-only recovery policy;
- runtime decision ageing without evidence deletion;
- cross-domain incident-key reuse rejection;
- evidence filename traversal rejection.

## Security claims intentionally not made

v2.9 does **not** claim:

- tamper-proof or legally certified forensic storage;
- hardware-backed incident signing unless a real provider is installed;
- remote attestation;
- automatic network or vehicle recovery;
- physical interlock verification;
- ISO 26262 / ASIL safety certification;
- incident-response certification;
- guaranteed protection from a privileged same-process attacker;
- protection when an attacker controls both the evidence file and its signing key;
- real hardware HIL coverage.

## Follow-up

The next high-value phase should harden the real hardware bridge boundary: authenticated Pi/bridge telemetry and command envelopes, per-device enrollment, replay resistance, bounded packet parsing, non-finite/range validation, and explicit bench/HIL safety interlocks before any real CAN/serial actuation testing.
