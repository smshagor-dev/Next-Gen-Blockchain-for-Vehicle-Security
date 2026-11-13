# OmniGuard V2X research evidence status

Updated: 2026-11-13. This is a **claim-gated status matrix**, not a finished paper.
Distinguish implemented code, observed source-data analysis, deterministic
software verification and independent empirical research.

| Workstream | Status | Verified engineering/source evidence | Remaining scientific gate |
| --- | --- | --- | --- |
| Arduino serial authentication (draft, not validated) | PARTIAL — NEW DRAFT | Signed enrolled-device envelope required; bounded reads, MAC/freshness/replay checks before ledger mutation, port closed on quarantine; synthetic tests added | CI/local execution, serial firmware protocol interoperability, independent wired emergency-stop and HIL validation missing |
| Hardware TCP ingress, bound messages, authenticated node sessions, replay and safety gate | MERGED, LAB VALIDATION BLOCKED | PR #74 was merged; source regression and GitHub security CI addressed software controls | Physical Pi/CAN bench and local emergency safety case not independently verified |
| V2X event admission | MERGED SOFTWARE PROTOTYPE | PR #80 merged opt-in off/shadow/enforce, authenticated-session-before-quorum policy; command-smuggling regression tests | Independent incident labels, prior-art originality analysis, correlated reporters and physical safety validation |
| Network collusion and availability fault checks | NEW DRAFT PR #89 (issue #88) | Actual merged EvidenceAdmissionGate and research-only ConsistentSubsetAdmissionGate exercised on 13 scripted incidents with seed/jitter variations, selected-source roles and SHA manifests | Constructed fault models, not independently captured physical incidents or repeated simulator trials; published comparator and HIL evidence missing |
| Source-CAM integrity | VERIFIED IMPORT, not event truth | PR #82 merged; official VeReMi NextGen v1.0.0 baseline and dataReplay archives SHA-verified and imported; receiver duplicates audited | CAM attacker bit does not mean a verified hazard incident or physical source attestation; distribution license review |
| Auxiliary Highway CAM detection | DRAFT PR #85, REPRODUCED | Official SHA-verified Highway_2 dataReplay single-source Test: 18,892 unique fingerprints; temporal comparator F1 25.05% (post-hoc) | Untouched independent simulator/split, published detectors, uncertainty; no incident truth |
| Auxiliary Urban transfer | DRAFT PR #87, EXPLORATORY REPRODUCED | Fixed Highway Validation thresholds transferred to Urban_2 Test (113,779 fingerprints), source SHA verified, temporal comparator F1 26.06% | Only one new scenario; source selection after Highway results; no independent seeds or confirmatory significance |
| Incident truth and split hygiene | STRUCTURAL ONLY | PR #83 merged structural source/group split audit | Independent world-state incident labels, label-review procedure, source license and temporal leakage still unverified |
| Realistic in-vehicle CAN source | BLOCKED | No licensed original CAN trace linked to independently annotated V2X hazard state | Verify source, license, timing, physical attack model and authorization boundary |
| Ledger crash safety and contract finality | DRAFT PR #90 — LOCAL CHECKPOINT RESEARCH ONLY | Experimental `experiments/ledger/crash_checkpoint.py` verifies local Go snapshots, fsyncs temporary files, uses atomic replacement and POSIX directory fsync; 10 fault-injection tests include real subprocess exits | Not wired into production Go persistence; no real power-loss/HIL validation, server-signed receipt finality or trusted monotonic host-rollback anchor |
| Statistical validation | TOOLING ONLY | PR #77/#78 merged exploratory no-false-significance reporting, paired bootstrap/sign-flip/Holm code | Independent seed execution, preregistered analysis, baseline/ablation comparisons, CIs/effect sizes using **actual** incident data |
| Runtime scaling and network availability | UNVERIFIED | Existing quick unit and deterministic simulation tests are not a representative runtime benchmark | Real network delays/partitions with measured CPU/RAM/tail latency and physical isolation |
| Novelty and paper evidence | NOT ESTABLISHED | Evidence-gated multi-source corroboration is a mechanism candidate, **not** new cryptography | Published prior-art comparison, distinguishable formal claim, valid ablations, reproducible multi-scenario independent datasets |

## 2026-11-13 — CAN command authorization boundary (draft PR #99)

- **Implemented, not yet test-verified:** `ECUCommandGateway.send_safe_mode_stop`
  now refuses all CAN actuation even when the bench gate is armed and the
  transport is initialized. Existing CAN frame checksums provide neither
  receiver authentication nor replay resistance. Removed misleading
  "fallback to serial" diagnostic. Two regression tests assert that CAN
  dispatch cannot reach the bus or frame builder.
- **Blocked:** a versioned ECU receiver protocol, directional command keys,
  durable replay state, independently wired emergency controls, hardware
  interlock measurements, and physical/HIL evidence. Local emergency controls
  must remain independent of this remote software path.
- **Next code task:** implement an authenticated receiver/acknowledgment
  simulator and fault-injection tests before considering any CAN re-enable.
  Never interpret synthetic tests as a vehicle safety certification.
- **Verification gate:** `python -m unittest tests.test_arduino_authenticated_ingress -v`;
  not executed in this change. Keep PR draft pending CI and review.

## 2026-11-13 — command protocol conformance and negative evidence

- **Implemented:** eight isolated protocol tests in
  `tests/test_hardware_command_protocol_conformance.py` covering directional
  HMAC key separation, single-use nonce, direction confusion, MAC tamper,
  stale timestamp, identity binding, unsafe-command rejection, and the
  **known restart replay vulnerability**.
- **Important negative evidence:** the final test deliberately demonstrates
  that a newly initialized in-memory verifier accepts a previously authenticated
  command while it remains fresh. This is **not** durable replay protection.
  A production receiver must persist monotonic sequence/nonce state with
  crash-safe storage or an independently authenticated challenge/response
  session before any actuation is allowed.
- **Blocked:** firmware receiver, signed acknowledgment, independent
  interlock/e-stop, physical CAN bus isolation, power-loss tests and HIL.
  No vehicle command was transmitted.
- **Verification:** `python -m unittest tests.test_hardware_command_protocol_conformance -v`
  and `python -m unittest tests.test_arduino_authenticated_ingress -v`
  are required; tests were not executed in this connector session.

## 2026-11-13 — authenticated TCP write-amplification boundary

- **Implemented, unverified:** the Pi TCP session now has an independent
  `SMARTCAR_HW_MAX_FRAMES_PER_SESSION` ledger-mutation budget (default 256,
  bounded to 1–10000). After the budget is exhausted the connection is
  rejected before another ledger write or remote command dispatch.
  This addresses authenticated-peer write amplification beyond the existing
  byte-framing and session-lifetime limits; it does not solve distributed
  DoS or a large number of new connections.
- **Synthetic regression added:** `tests/test_pi_authenticated_session_budget.py`
  sends two separately signed telemetry envelopes over a fake socket with
  budget=1, asserting exactly one blockchain mutation. No real TCP network
  or physical ECU was exercised.
- **Verification command:** `python -m unittest discover -s tests -p 'test_pi_authenticated_session_budget.py' -v`.
  **Not executed:** the local checkout could not resolve github.com.
- **Next engineering task:** enforce server-wide connection/rate quotas,
  durable replay state, signed command acknowledgment, firmware conformance
  and independent emergency-stop/HIL safety evidence. PR #99 remains draft.

## 2026-11-13 — aggregate Pi ingress rate bound (draft PR #99)

- **Implemented, unverified:** `GlobalTelemetryBudget` uses a monotonic
  single-process token bucket (default 32 accepted frames/sec, burst 64)
  shared across all sequential Pi TCP sessions. The budget is claimed after
  MAC/replay/schema verification and before ledger mutation or actuation.
  A rejected over-budget frame closes its connection. Four deterministic
  regression cases cover burst/refill, reconnect sharing, clock rollback,
  and configuration bounds.
- **Limits:** this is neither a distributed quota nor a network-level
  SYN/connection admission defense. Repeated unauthenticated connections
  still consume accept/verification CPU; separate admission and firewall
  controls remain necessary. Serial mode does not use this TCP budget.
- **Verification required:** `python -m unittest discover -s tests -p
  'test_global_telemetry_budget.py' -v` and focused hardware security tests.
  No execution or HIL evidence obtained in this connector run.
- **Next code:** bound pre-auth connection acceptance per source and total
  verification work, then implement crash-safe replay/session handshake
  with receiver acknowledgments before considering CAN enablement.

## 2026-11-13 — TCP rate-limit syntax repair and unsafe helper removal

- **Code repaired, execution pending:** The preceding aggregate-rate-budget
  change introduced literal backslash-n text into Python control-flow lines.
  Replaced those invalid source tokens with actual line breaks so the
  `GlobalTelemetryBudget` construction and budget check are syntactically
  structured. Removed the unused unsigned ECU serial command writer entirely,
  leaving the existing fail-closed dispatch policy in place.
- **Verification gate:** run `python -m py_compile hardware_bridge.py`,
  `python -m unittest discover -s tests -p 'test_global_telemetry_budget.py' -v`,
  and the full hardware security regression suite. Not executed: container
  cannot resolve github.com and no executable checkout is available.
- **Remaining:** pre-auth connection quotas, durable replay state,
  authenticated ECU receiver acknowledgments, independent local emergency
  wiring and hardware-in-the-loop validation. Draft PR #99 must not merge
  without executable checks.

## 2026-11-13 — TCP pre-authentication DoS boundary

- **Implemented on draft PR #99:** server-wide monotonic token bucket for TCP
  connection admission (defaults: 4 accepts/sec, burst 8), charged before
  untrusted parsing or MAC verification; unauthenticated sessions have a
  3-second default absolute authentication deadline independent of trickle
  bytes (configurable 1–15 seconds). Authenticated sessions regain the
  normal idle timeout. Three deterministic budget unit tests added.
- **Unverified:** tests were not executed in this connector run. Commands:
  `python -m unittest tests.test_pre_auth_tcp_admission -v` and
  `python -m unittest tests.test_hardware_bridge_security -v`.
- **Remaining gaps:** blocking single-threaded accept architecture, kernel
  backlog exhaustion, host-wide distributed DoS, durable replay protection,
  ECU authenticated acknowledgment, physical interlock and independent E-stop
  tests. Connection budget is process-local and resets on restart. This is
  a software mitigation, not a publishable network resilience measurement.
- **Next code task:** socket-level fake-clock tests of partial frames and
  auth deadline, then nonblocking bounded connection handling under load.

## 2026-11-13 — TCP post-receive deadline enforcement

- **Implemented in draft PR #99:** cap blocking `recv` timeout by the
  remaining absolute session lifetime and authentication deadline, then
  recheck both boundaries **after** `recv` returns and before verifying or
  admitting any telemetry. This closes the boundary where a signed frame
  received after the deadline could otherwise reach the ledger.
- **Synthetic tests added (not executed here):**
  `python -m unittest tests.test_hardware_transport_deadlines -v`;
  covers exact authentication expiry, authenticated post-auth traffic,
  session expiry and pre-deadline acceptance.
- **Partial:** per-connection handling remains sequential; one client can
  consume its allowed deadline before the next is serviced. Server-wide
  admission/rate budgets are not equivalent to bounded concurrent service.
- **Blocked:** CI execution, real socket fault injection, restart-persistent
  replay state, receiver acknowledgments, firmware/HIL tests and independent
  physical emergency-stop. No hardware safety or publishable latency claim.
- **Next code task:** socket-level Slowloris tests with real loopback
  connections and bounded concurrent session scheduling.

## 2026-11-13 — hardware mode dispatch fail-closed review

- **Implemented in draft PR #99:** reject unknown or empty
  `SMARTCAR_HW_MODE` values instead of implicitly entering the Arduino
  serial ingress path. Only explicit `pi` and `arduino` values dispatch.
  Four new synthetic dispatch regressions check invalid/empty values,
  explicit selections, and teardown after invalid configuration.
- **Verification:** `python -m unittest tests.test_hardware_mode_dispatch -v`
  and `python -m compileall -q hardware_bridge.py tests` are required.
  GitHub commits were accepted, but tests could not be executed in the
  current environment because the local GitHub checkout is unavailable
  (DNS lookup failed). No passing tests or physical validation claimed.
- **Next engineering task:** independent socket-level slow-client and
  concurrent-admission experiments, followed by crash-safe replay
  protection. The server still handles connections sequentially.
- **Research evidence:** none from this change; this is a security
  correctness fix, not a publishable scientific experiment.

## Research assertion / results gate

- Real VeReMi CAM results are **auxiliary message-manipulation detection**
  observations, not experiments proving false hazard-event admission rates.
- Thirteen scripted adversarial incident cases include single/multiple malicious
  enrolled identities, incident-ID first-writer preemption, copied digest,
  session-unverified report, repeated identity, displaced/stale reporters,
  remote-action-field smuggling and lost honest corroboration. These are
  deterministic **software verification** only, not independent research.
- The campaign's apparent scenario rates must never be presented as
  detection accuracy, model uncertainty, independent statistical samples,
  vehicle safety, post-quantum security or a publication-grade result.
  Deliberately failing cases (colluding malicious quorum, partition-induced
  missed true alerts) are essential negative evidence, not benchmarks.
- The bounded **consistent-subset** research alternative removes first-reporter
  location/time reference dependence for compatible honest subsets. It is not
  integrated into V2XHub and is still vulnerable to malicious collusion,
  report-pool exhaustion and lost honest corroboration. A constructed scenario
  demonstrating the difference is **not** proof of originality or superiority.
- No physical hardware, external vehicle, road test, or HIL evidence has
  been observed in this session. No vehicle actuation is performed.
- A later paper may use only immutable verified actual-source evidence with
  source/metric mapping, defensible independent units, accurate citations,
  comparative baselines, uncertainty and limits. A software QA report is
  **not** an original research paper.

## 2026-11-13 Arduino branch correctness repair

- PR #99: corrected literal escaped newline tokens that made the `maybe_send_arduino` call invalid Python syntax (commit `15e1b0e`). Corrected test frame delimiter handling so it removes the actual LF byte rather than backslash and letter `n` (commit `4c7dae3`).
- These are **source-level fixes only**; tests have not been executed in this run. Do not count regression coverage as passing or claim device interoperability.
- Immediate next validation: `python -m py_compile hardware_bridge.py tests/test_arduino_authenticated_ingress.py` and `python -m unittest tests.test_arduino_authenticated_ingress -v` in an environment with project dependencies. Keep PR draft until executed and reviewed.
- Next engineering task: directional key separation and firmware conformance, without changing local independent emergency control.

## Next substantive code tasks

1. Build a verified incident-level world-state annotation bridge, keeping
   original VeReMi CAM attacker labels separate and explicit provenance.
2. Turn constructed source-enrollment, collusion, preemption, report-pool
   saturation and network-partition cases into independently executed,
   externally verified incident traces; quantify false accepts and missed
   honest hazards under identical candidate/baseline conditions.
3. Replace scripted truth and delivery flags with authenticated captured
   sessions and independently verified simulation world truth.
4. Run matched published comparators and multiple independently simulated
   seeds/scenarios, pre-register hypotheses, preserve raw evidence and
   evaluate uncertainty/effect sizes before writing numeric manuscript claims.

## Local Go ledger crash-checkpoint evidence boundary (PR #90)

The research-only local checkpoint validates snapshot block hashes against the
existing Go ledger verifier before writing and refuses a different historical
prefix relative to the **currently available** checkpoint. A bounded JSON
checkpoint is written to a temporary file, flushed/fsynced, atomically
replaced and directory-fsynced on POSIX. Fault-injection tests include actual
POSIX subprocess `os._exit(73)` at three durability stages, malformed and
truncated checkpoints, generation mismatch and recovery of complete old/new
states. These verify software behaviour on the tested OS/filesystem, **not**
physical power-loss durability or distributed consensus finality.

Two deliberate failure cases must remain visible: a host can restore a valid
older checkpoint after restart because no externally trusted monotonic anchor
exists, and unkeyed SHA-256 hashes can be recomputed over forged receipt
metadata. Hence the prototype provides neither cryptographically authenticated
smart-contract finality nor host-rollback resistance. No HIL/vehicle safety
claim or submission-ready experimental result follows from these tests.

## Arduino authenticated serial boundary (2026-11-13)

Draft branch `authenticate-arduino-serial-ingress` removes raw unsigned Arduino JSON acceptance and uses the existing direction-separated envelope verifier. Devices must emit a complete signed TELEMETRY envelope per newline, using `SMARTCAR_HW_DEVICE_KEYS_JSON`. The port is closed on framing/authentication error, not automatically reconnected. This is a **breaking wire-protocol change** and requires a matching firmware sender; serial source keys can be extracted from compromised firmware. Serial confidentiality, durable anti-replay across process restarts, independent emergency wiring, and physical validation remain blocked. The pre-existing Arduino SAFE_MODE_STOP output is still governed by the bench actuation gate; it is not independently authenticated to firmware. No physical actuation has been tested. Synthetic tests are not publication evidence.

## Arduino command authenticity (draft PR #99, 2026-11-13)

- Arduino ingress accepts enrolled HMAC TELEMETRY envelopes; unsigned JSON is rejected before ledger mutation.
- Outbound Arduino bench `SAFE_MODE_STOP` now uses an authenticated `COMMAND` envelope bound to the verified device identity, replacing unsigned serial JSON. A regression checks command verification and the disarmed interlock.
- **PARTIAL / BLOCKED:** firmware must independently verify command MAC, replay nonce, freshness and safe local interlocks before any actuator response. The same enrolled symmetric secret is currently used in both directions; key separation and durable replay state remain unimplemented. No physical actuation or HIL evidence. Tests are pending execution; no research result follows from this patch.
- **NEXT:** execute focused regressions; add firmware protocol conformance vectors, directional key separation and independent emergency-stop validation.

## Authenticated Arduino serial denial-of-service boundary (draft PR #99, 2026-11-13)

- PARTIAL / UNVERIFIED: Arduino authenticated ingress now has bounded session lifetime (5–600 s) and inactivity timeout (1–30 s), in addition to bounded frames and fail-closed framing. Two synthetic regression tests cover silent and trickle-fed peers; tests have **not** been executed in this connector run.
- BLOCKED: firmware interoperability, durable anti-replay, directional key separation, independent local emergency-stop and physical bench interlock validation. The same enrolled secret currently signs both directions, so do not claim directional key isolation.
- UPCOMING: execute `python -m unittest tests.test_arduino_authenticated_ingress -v`, correct failures, implement independent inbound/outbound keys, then conduct isolated hardware bench tests before any physical actuation claim.
- EVIDENCE CLASS: software change and unexecuted regression tests only; **not** incident-level scientific data, vehicle safety validation, or publishable performance evidence.

## ECU command transport fail-closed boundary (2026-11-13, draft PR #99)

- **PARTIAL / CODE CHANGED:** ECU gateway no longer falls back from failed CAN initialization to the unsigned serial actuator protocol. Explicit ECU serial mode also remains disabled; no unsigned serial dispatch is reachable through `send_safe_mode_stop`. Local emergency control remains independent of remote command dispatch.
- **REGRESSION COVERAGE ADDED, NOT EXECUTED:** `test_failed_can_does_not_downgrade_to_unsigned_serial` and `test_explicit_unsigned_ecu_serial_is_disabled`. Run `python -m py_compile hardware_bridge.py tests/test_arduino_authenticated_ingress.py` and `python -m unittest tests.test_arduino_authenticated_ingress -v`, plus hardware security suite, before considering merge.
- **BLOCKED:** No authenticated ECU serial protocol or hardware safety case; CAN command payload itself is not cryptographically authenticated. A wired independent emergency-stop, firmware acceptance tests, replay durability and HIL remain unverified. These changes cannot support vehicle safety or research-effectiveness claims.
- **UPCOMING:** Add a verified authenticated ECU command protocol or permanently remove dead serial command code; test CAN failure/transport downgrade under fault injection and run actual regressions.
