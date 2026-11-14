# Physical hardware safety evidence: independent test-bench protocol

**State 2026-11-13: NOT EXECUTED. Physical evidence not available.**
This is a *test-readiness checklist*; it must not be described as results.

## Scope and safety constraints

Use a controlled low-voltage, current-limited bench with dummy-load outputs,
not a public-road vehicle or a moving drivetrain. Qualified lab staff must
provide an **independent, accessible mechanical emergency-stop and hardwired
power isolation**, separate from Pi, V2X network, smart contracts and the
software under study. Do not arm vehicle actuation, defeat safety interlocks,
bridge vehicle control buses, or bypass a hardware stop to obtain results.

Recording the output of a software simulation or GPIO mock as if it were an
actual emergency-stop or CAN/ECU test is forbidden. The code in this branch
does not connect to GPIO, serial, CAN, actuators, bench power or physical E-stop.

## Required independent artifacts per session

- Bench identifier, instrument calibration and firmware build provenance.
- Schematic identifying the independent hardwired stop and non-actuating
  dummy-load output, with responsible safety review.
- Operator log and second witness sign-off, time- and role-separated.
- Hardware firmware SHA-256, configured key-enrollment provenance, verified
  serial HMAC protocol version and declared test setup.
- Signed/raw oscilloscope or logic-analyzer capture of local stop line and
  network/serial telemetry with calibrated time axes. Include instrument
  serial number and raw file hash.
- Raw authenticated communication capture preserving failures and dropped
  messages; node identities pseudonymized.
- CAN/serial traces from physically isolated, dummy-load-only test equipment,
  including bus errors and unprocessed frames; no live vehicle access.
- Explicit pass/fail rows and maximum observed local stop latency from
  repeated *physically witnessed* trials with measurement uncertainty.

## Proposed non-destructive physical acceptance experiments

| ID | Experiment | Minimum evidence and failure condition |
| --- | --- | --- |
| HIL-01 | Power-up disabled | Inert output after power-on/reboot without explicit bench arm; raw output trace |
| HIL-02 | Independent hardware stop | Separate stop switch physically removes dummy-load authority despite software/network state |
| HIL-03 | Gateway or network loss | Local independent stop path still works while V2X/ledger unavailable |
| HIL-04 | Unsafe/unsigned telemetry | Invalid messages fail closed before any state-changing command |
| HIL-05 | Replay after restart | Previously admitted signed command rejected after process restart using retained nonce storage |
| HIL-06 | Wrong enrolled device | Swapped identity/MAC rejected, with physical output remaining inert |
| HIL-07 | Delayed or duplicated acknowledgment | Simulation ACK not mistaken for physical execution; no repeated actuation |
| HIL-08 | Serial overflow/framing fault | Oversized, partial and malformed frames fail closed without resource exhaustion |
| HIL-09 | Power interruption | Independent stop and safe reboot behavior measured using instrumented low-voltage bench |
| HIL-10 | Worst-case local stop latency | Source-backed distribution and measurement uncertainty under isolated induced network loss |

Each row must have a session ID, start/end time, independent witness,
instrumented evidence hash, immutable source firmware hash, expected condition,
observed outcome and pass/fail reason. Failed rows remain in the report.

## Submission gate

**BLOCKED until physical observations exist.** A green GitHub CI run proves
software tests only. A signed declaration without instrument traces is
insufficient. SHA-256 alone establishes byte integrity, not test authenticity,
operator independence or physical causation. Approval requires an independent
hardware safety review; no automotive safety certification is claimed.

## Research-code pairing

The non-actuating software campaign is:
\`python -m experiments.v2x.stochastic_world_trials --output-dir experiment-artifacts\`

Its manifest deliberately declares \`physical_hardware_validated=false\` and
\`independent_external_incident_labels=false\`. Never replace those flags with
\`true\` without authentic external evidence and independent review.
