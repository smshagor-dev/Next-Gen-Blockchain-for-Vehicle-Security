# Research protocol: corroborated V2X incident admission

**Status:** BOUNDED PROTOTYPE; original contribution not yet demonstrated by independent literature comparison or external experiments. No new cryptographic primitive, post-quantum claim, Sybil resistance, physical sensor attestation, or automotive safety certification is introduced.

## Falsifiable proposal

Research hypothesis: requiring consistent observations from separate **already-enrolled, session-authenticated node identities** before broadcasting a network hazard assertion reduces *false acceptance* from a compromised single enrolled node, at a measurable cost in *alert availability* and *time to corroborate*, compared with authenticated-only forwarding.

This is not automatically novel. Prior work on multi-source corroboration, V2X trust, quorum admission, reputation, and misbehavior detection must be compared on identical real data before a novelty claim is considered.

### Authenticated transport boundary

\`V2XHub._handle_msg\` verifies a sender's session MAC, timestamp, bound identity and replay nonce before the evidence policy is invoked. \`SMARTCAR_V2X_EVIDENCE_POLICY=off\` is the default; \`shadow\` makes non-authoritative decisions without changing traffic; \`enforce\` suppresses forwarding of ALERT/V2I_SIGNAL messages unless the policy returns **relayed=True**.

This is **network assertion relaying only**. It must NOT authorize or delay local collision-avoidance/braking; no consensus round, hub or remote message may be in the safety-critical local stop path. Local validated hazard control must continue to operate during network partitions and missing corroboration.

### Canonical evidence payload

Each opt-in ALERT / V2I_SIGNAL payload needs:

    {"evidence": {
      "incident_id": "hazard-0001",
      "event_class": "ROAD_HAZARD",
      "observed_at": "2026-11-12T16:00:00+00:00",
      "lat": 51.5000, "lon": -0.1000,
      "sensor_sha256": "64-lowercase-hex-of-local-observation"
    }}

Allowed event classes: COLLISION, OBSTACLE, ROAD_HAZARD, TRAFFIC_CONTROL.
Transport identity comes from the verified **connection**, never from this
payload. The incident ID is a grouping hint supplied by senders, not a
cryptographic identity; hash fields only record sender-claimed observation
digests and do **not** prove hardware origin or prevent collusion.

### State transition and invariants

Each incident starts UNSEEN. First eligible authenticated report enters
PENDING, unique corroboration with class consistency, geospatial distance
<=100m, event time delta <=5s and independent sensor digests transitions
PENDING -> ACCEPTED. The first threshold crossing triggers **one** broadcast.
Further messages for that incident within TTL are not rebroadcast in ENFORCE
mode. Invalid observations are REJECTED without incrementing the vote count.

- I1: Each relay requires >=2 **different authenticated session IDs' enrolled node identities** (not two packets from the same identity).
- I2: A source cannot increase count twice even by changing the message nonce or digest.
- I3: One incident produces at most one evidence-gate broadcast per 20-second TTL.
- I4: Active incidents are memory capped (default 2,048); at capacity, newly observed incident IDs are rejected rather than evicting live state.
- I5: MAC/replay verification failure never contributes a report to the evidence gate.
- I6: Local emergency control cannot be routed through this gate, and remote event relaying must never imply actuation authorization.

Note that "independent identities" is **not** statistical independence:
enrolled vehicles can collude and false-report the same incident. Incident
IDs and digests are self-asserted. A partition can indefinitely suppress a
true remote hazard message until the TTL expires. Consequently, no full
safety guarantee or Sybil resistance is claimed.

### Config

    SMARTCAR_V2X_EVIDENCE_POLICY=off | shadow | enforce
    SMARTCAR_V2X_EVIDENCE_QUORUM=2
    SMARTCAR_V2X_EVIDENCE_MAX_INCIDENTS=2048

Use SHADOW for initial vehicle-network study to quantify rejection and
availability without hiding information. ENFORCE changes application behavior
and must not be enabled in a safety-critical environment before full
fault-injection, review and a separate local control safety case. The default
is OFF for compatibility.

### Research questions and evaluation protocol

- **RQ1**: Compared with authenticated-only forwarding, how do false
  assertion admissions change under 1 compromised enrolled source, 2 colluding
  sources, copied evidence digests, and replayed authenticated messages?
- **RQ2**: How does quorum change the missed legitimate hazard rate and
  time-to-alert under node loss, unequal reporting schedules, network delay
  and partitions?
- **RQ3**: How sensitive are false acceptance and availability to changes in
  time/geographic tolerance, quorum and incident TTL?
- **RQ4**: What are the latency and memory costs at 10, 50, 100, 500,
  and 1,000 authenticated participants, with up to 30% compromised?

Required baselines/ablations: (B1) authenticated-only forwarding (current
default), (B2) compatible published trust/misbehavior detector, (A1) reduced
corroboration, (A2) relaxed spatial bounds, (A3) stricter corroboration.
Compare same packet traces and independent repeated seeds; freeze metrics,
attack scripts and held-out partitions before final evaluation.

Metrics MUST separate **message-level** decisions from **incident-level**
recognition, FP/FN and latency; report class balances, uncertainty, false
negatives under partitions, and results from malicious but enrolled identities.
Never use CI unit-test scenarios, a four-row fixture, or message-count formulas
as independent research outcomes.

### Evidence gaps preventing submission

External dataset origin/license, labels, mapping from VeReMi/CAN source to
these evidence fields, cross-source corroboration truth, local HIL safety
validation, multi-node network performance, independent repetitions, ablation
results, published baselines, preregistered statistics and frozen protocol
are still missing. This PR is a mechanism candidate + tests only.
