# World-state incident universe and hub receipt integrity protocol

Status: **engineering contract only**. No independent incident labels, actual
vehicle captures, or publishable outcomes have been supplied.

## Critical scientific correction

An incident-level evaluation cannot derive its denominator only from
received network assertions: a positive world incident with **no packet**
would disappear, systematically hiding some false negatives under partitions.
The joiner counts all world-state annotated incident opportunities, even if
they have no captured message. Unobserved positives become false negatives,
while explicitly enumerated negative opportunities become true negatives
unless forwarded. Negative opportunities must be carefully defined by an
independent annotation protocol; they are not all possible road-time windows.

The two inputs are independent **artifacts**, not proven independent
sources of truth. A SHA-256 match verifies bytes, never physical truth.

## Input A: incident world-state CSV

Required fields:
- source_id, scenario_id, seed, group_id, split, incident_id
- label (1 = real incident, 0 = explicitly observed negative opportunity)
- label_provenance, world_event_at (timezone-aware)

One source/scenario/seed per file; every incident ID unique, and the
original group-split audit must pass. Only split=test is accepted in
this tool. The audit refuses CAM attacker flags as incident truth.
For positive incidents, packet times cannot precede the world event.

A genuinely independent simulator world-state export and label review are
not yet available. A manually entered annotation string is self-attested
even if it passes this software audit.

## Input B: hub-exported V2X ALERT NDJSON

Each JSON object has exactly:
- capture_id, source_id, scenario_id, seed, seq, received_at
- session_verified (boolean hub export claim), bound_sender_id
- message (original structured V2X ALERT with nonce, timestamp, sender ID,
  payload.evidence, and security envelope)
- export_mac (lowercase HMAC-SHA256 hex)

The MAC is HMAC-SHA256 over the canonical UTF-8 JSON serialization of
the **entire object except export_mac**, sorted keys, compact separators,
UTF-8 with ensure_ascii false, no NaN, using an exporter secret key of
at least 32 bytes. The key must be a separate private file and must
never be stored in a repository or result.

This MAC only verifies possession of the **hub export key**. It does NOT
independently verify the original V2X sender MAC, session handshake,
source enrollment or physical measurement. The session_verified flag
is the hub exporter's integrity-bound claim, NOT an independent
cryptographic verification by this program. A genuine exporter must
set it from the actual validated live session, not from an attacker
supplied input field.

The tool checks HMAC, externally pinned file digests, bound identities,
unique receipt IDs, verified-message replay nonces, monotonic sequence/time,
freshness, strict incident evidence schema and exact world incident ID join.
No captured incident without an annotated world label is accepted. Zero
captured records are allowed if the world universe is nonempty.

## Input C: source metadata

A separate JSON object must declare:

source_id, scenario_id, seed, world_sha256, capture_sha256,
world_source, world_label_protocol, world_label_reviewer,
hub_export_origin, capture_verifier_version, source_commit, license.

All fields must be present and nonempty (seed must match as an integer).
World and capture digests also need to be supplied **independently** as
explicit CLI flags, and they must match the files and metadata. The
metadata itself is self-reported, not an external certification of
the claimed origin, licensed distribution, annotation review, or session
security.

## CLI

    python -m experiments.v2x.join_world_capture \
      --world-csv /path/to/independently-reviewed-world.csv \
      --hub-capture-jsonl /path/to/hub-export.jsonl \
      --metadata /path/to/source-metadata.json \
      --exporter-key-file /private/exporter-key.bin \
      --expected-world-sha256 ACTUAL_PINNED_WORLD_SHA256 \
      --expected-capture-sha256 ACTUAL_PINNED_CAPTURE_SHA256 \
      --output-dir /path/to/results

Outputs:
- joined_incident_capture.csv — capture-only rows with labels joined from
  the separate world universe.
- joined_incident_policy_decisions.csv — authenticated-only, quorum-2,
  quorum-3 and wider-radius decisions from the same accepted capture rows.
- joined_incident_world_results.json — full-world TP/FP/TN/FN and
  world-to-forward latency, including unreceived positives/negatives.
- joined_incident_evidence_manifest.json — SHA-256 source/result digests.

The output always reports publication_ready=false,
independent_world_truth_verified=false, and
original_v2x_session_mac_independently_reverified=false.

## Research barriers

Real external independent incident annotation, authenticated captured
packet sessions, source/license verification, complete negative-opportunity
sampling, multi-seed simulations, published baselines, recorded vehicle
faults, CPU/RAM/tail latency, and HIL local emergency-control safety have
not been provided. Merely passing fabricated contract tests cannot
establish an original scientific contribution.

The tool intentionally does not change the production V2XHub,
transport authentication, local braking, CAN, ECU or ignition policy.
