"""Non-actuating negative control: an in-memory hardware nonce pin disappears on restart.

Run: python -m research_contracts.hardware_restart_replay_control
Only COMMAND envelope verification is exercised; no socket or actuator is opened.
The result is a protocol counterexample, not an attack-detection measurement.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone

from hardware_transport_security import (
    HardwareEnvelopeVerifier,
    HardwareTransportError,
    build_authenticated_envelope,
    build_safe_stop_payload,
)

DEVICE = "bench-device"
SECRET = "research-only-nonproduction-secret-0123456789"
NONCE = "0123456789abcdef0123456789abcdef"


def _verifier():
    return HardwareEnvelopeVerifier({DEVICE: SECRET})


def run_control():
    now = datetime.now(timezone.utc)
    envelope = build_authenticated_envelope(
        DEVICE, SECRET, "COMMAND",
        build_safe_stop_payload(block_index=1, timestamp=now),
        timestamp=now, nonce=NONCE,
    )
    first = _verifier()
    first.verify(envelope, expected_kind="COMMAND")
    same_process_rejected = False
    try:
        first.verify(envelope, expected_kind="COMMAND")
    except HardwareTransportError as exc:
        same_process_rejected = exc.reason == "HW_REPLAY_DETECTED"
        if not same_process_rejected:
            raise

    # New interpreter, new verifier, identical authenticated bytes and key.
    # This isolates the persistence boundary rather than merely re-instantiating
    # a verifier in the same Python process.
    child = subprocess.run(
        [sys.executable, "-m", "research_contracts.hardware_restart_replay_control", "--child"],
        input=json.dumps(envelope), text=True, capture_output=True,
        timeout=10, check=False,
    )
    if child.returncode != 0:
        raise RuntimeError("restart control failed: " + child.stderr[-500:])
    restarted = json.loads(child.stdout)
    if not same_process_rejected or not restarted["accepted_after_restart"]:
        raise AssertionError("unexpected replay control outcome")
    return {
        "protocol": "hardware-envelope-v1",
        "scenario": "identical_mac_valid_envelope_replayed_after_process_restart",
        "same_process_replay_rejected": same_process_rejected,
        "accepted_after_restart": restarted["accepted_after_restart"],
        "physical_actuation": False,
        "claim_scope": "negative_control_only",
    }


def _child():
    envelope = json.load(sys.stdin)
    verifier = _verifier()
    try:
        verifier.verify(envelope, expected_kind="COMMAND")
    except HardwareTransportError as exc:
        print(json.dumps({"accepted_after_restart": False, "reason": exc.reason}))
    else:
        print(json.dumps({"accepted_after_restart": True}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.child:
        _child()
        return
    result = run_control()
    serialized = json.dumps(result, sort_keys=True, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(serialized + "\n")
    print(serialized)


if __name__ == "__main__":
    main()
