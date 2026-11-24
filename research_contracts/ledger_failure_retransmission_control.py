"""Non-actuating, real-verifier ledger-failure/retransmission negative control.

This is NOT a durability or safety proof. It deliberately demonstrates the
verification-before-ledger-commit gap using the production envelope verifier.
No hardware or network sockets are opened.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope,
)

DEVICE = "ledger-fault-bench"
SECRET = "research-only-not-a-production-secret-" + "X" * 40


def payload(now):
    return dict(
        source="fault_injection", timestamp=now.isoformat(), speed=12.0,
        acceleration=0.0, fuel_level=75.0, battery_voltage=12.5,
        engine_temp=55.0, gps_lat=0.0, gps_lon=0.0,
        obstacle_distance=50.0, emergency_brake_active=False,
        steering_angle=0.0, brake_pressure=0.0, throttle_position=0.0,
        rpm=1000.0, odometer=10.0, driver_heart_rate_bpm=70.0,
        driver_drowsiness_score=0.0, driver_unwell=False,
        event="RESEARCH:LEDGER_FAULT",
    )


def run_case(fail_first):
    now = datetime.now(timezone.utc)
    envelope = build_authenticated_envelope(
        DEVICE, SECRET, "TELEMETRY", payload(now),
        timestamp=now, nonce="a1" * 16,
    )
    verifier = HardwareEnvelopeVerifier({DEVICE: SECRET})
    committed = []
    attempts = []
    for attempt in range(2):
        try:
            verified = verifier.verify(envelope, expected_kind="TELEMETRY")
            # Model an injected ledger failure AFTER the actual production
            # verifier's replay claim, before any persistent ledger mutation.
            if fail_first and attempt == 0:
                raise OSError("INJECTED_LEDGER_WRITE_FAILURE")
            committed.append(verified.payload["event"])
            attempts.append("committed")
        except HardwareTransportError as exc:
            attempts.append(exc.reason)
        except OSError as exc:
            attempts.append(str(exc))
    return dict(fail_first=fail_first, attempts=attempts,
                committed_count=len(committed),
                lost_valid_observation=(fail_first and not committed))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {
        "protocol": "real production HardwareEnvelopeVerifier, simulated ledger sink",
        "non_actuating": True,
        "fault": run_case(True),
        "control": run_case(False),
        "limitations": [
            "in-process injected OSError, not actual filesystem power loss",
            "no durable replay store or production ledger commit measured",
            "one deterministic envelope per case, not statistical evidence",
        ],
    }
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
