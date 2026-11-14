# Capturing non-actuating physical bench evidence for OmniGuard V2X

**No physical bench testing has been performed in this PR.** This document
describes what an independent qualified laboratory must supply before
the paper may discuss measured hardware safety.

The bench must remain an isolated low-voltage **dummy load**, with separate,
independent physical power-disconnect/emergency-stop hardware and independently
calibrated measurement instrumentation. Never use this unvalidated prototype
on a moving car, public road, safety-critical drivetrain, or live ECU.
Do not energize or bypass any physical safety mechanism for a software test.

## Instrument file format

One raw capture per HIL-01 through HIL-10. CSV must have **exactly**
these fields:

    elapsed_sec,hardwired_estop_asserted,dummy_load_enabled,network_link_available
    0.000,0,1,1
    0.010,1,1,0
    0.020,1,0,0
    0.030,1,0,0

The above is an **artificial schema illustration**, not a measurement. Binary
signals must be measured independently with suitable isolation, not inferred
from application logs. The clock must be monotonic and its calibration/
synchronization uncertainty separately reported.

At least HIL-02, HIL-03, HIL-09 and HIL-10 must contain a sampled stop-assertion
and dummy-load-off transition; HIL-03 also requires measured network link loss.
A missing transition or re-energization while the stop remains asserted
fails the digital consistency audit. This does NOT itself verify the cause of
the transition or bound true stop latency without calibrated analog evidence.

## Expected directory structure

    bench-session/
      manifest.json
      calibration.pdf
      HIL-01.csv
      HIL-02.csv
      ...
      HIL-10.csv

The calibration file may be any nonempty instrument-issued artifact; its
integrity is checked against the SHA-256 declared in the manifest. This tool
does not validate the issuer of that calibration file or its expiry date.

## Manifest format

    {
      "schema": "omni-non-actuating-bench-evidence-v1",
      "session_id": "lab-session-2026",
      "apparatus_id": "isolated-test-rig-1",
      "operator_id": "operator-code-1",
      "witness_id": "witness-code-2",
      "firmware_sha256": "FULL_64_HEX_FIRMWARE_BUILD_SHA256",
      "bench_configuration": "isolated_dummy_load_no_vehicle",
      "instrument": "scope-model-and-serial-record",
      "calibration": {
        "path": "calibration.pdf",
        "sha256": "FULL_64_HEX_CALIBRATION_FILE_SHA256"
      },
      "cases": [
        {
          "id": "HIL-01",
          "witness_id": "witness-code-2",
          "capture": {
            "path": "HIL-01.csv",
            "sha256": "FULL_64_HEX_RAW_CAPTURE_SHA256"
          }
        }
      ]
    }

The case array must include all 10 unique IDs HIL-01..HIL-10, each with
its matching raw capture and exact SHA-256. Compute hashes *after* export.
No keys, serial port credentials, identifiable participant data or private
machine paths should be committed.

## Run (reviewed bench artifacts only)

    python -m experiments.hardware.audit_physical_evidence \
      --evidence-dir /private/bench-session \
      --manifest /private/bench-session/manifest.json \
      --report /private/results/bench-integrity-report.json

The tool only checks completeness, path containment, SHA-256 integrity,
time monotonicity, sampled transitions and obvious unsafe sample sequences.
It **never** sets \`physical_hil_validated=true\`. It does not verify the
independence of an E-stop, the identity of a witness, instrument certification,
measurement sample rate, automotive functional safety or a physical cause.

A qualified reviewer must separately inspect original instrument files,
calibration certificates, hardware schematic, independent hardwired switch,
raw captures, threat model and all failure cases. A cryptographically signed
external review should be retained *outside* the repository. Hardware test
failures must not be filtered out. The manuscript cannot cite synthetic
CI fixture results as bench measurements.
