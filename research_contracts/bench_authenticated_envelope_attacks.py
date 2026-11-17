"""Authenticated replay/tamper experiment with independent attack labels.

Uses production signed-envelope builder and verifier plus a real SQLite store.
No TCP socket, vehicle, physical actuation, or claim of dataset realism.
Each independent seed provisions a new store; no attempt-level pseudoreplication.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import random
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hardware_nonce_store import SQLiteNonceStore
from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError
from datetime import datetime, timezone
from hardware_transport_security import build_authenticated_envelope, _NUMERIC_RANGES, _BOOL_FIELDS

DEVICE = "bench-node"
SECRET = "lab-independent-secret-0123456789abcdef-9876543210"


def signed_telemetry(nonce):
    now = datetime.now(timezone.utc)
    payload = {key: (low + high) / 2 for key, (low, high) in _NUMERIC_RANGES.items()}
    payload.update({key: False for key in _BOOL_FIELDS})
    payload.update(timestamp=now.isoformat(), event="BENCH_EVENT")
    return build_authenticated_envelope(
        DEVICE, SECRET, "TELEMETRY", payload, timestamp=now, nonce=nonce
    )


def run(seed, pairs, output):
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError("seed must be unsigned 64-bit integer")
    if type(pairs) is not int or not 1 <= pairs <= 100000:
        raise ValueError("pairs must be in [1, 100000]")
    rng = random.Random(seed)
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        store = SQLiteNonceStore(str(Path(directory) / "nonce.sqlite"),
                                 provision=True, max_claims=2 * pairs + 1)
        verifier = HardwareEnvelopeVerifier({DEVICE: SECRET}, durable_nonce_store=store)
        try:
            # Stage 1: explicitly prime nonce history with independently
            # signed, legitimate frames. No concurrency/order ambiguity.
            primed = []
            for i in range(pairs):
                nonce = hashlib.sha256(f"{seed}:prime:{i}".encode()).hexdigest()[:32]
                envelope = signed_telemetry(nonce)
                verifier.verify(envelope)
                primed.append(envelope)
            # Stage 2: independent attack labels determined before execution.
            workload = []
            for i, envelope in enumerate(primed):
                workload.append((f"{i}:replay", "replay", envelope))
                tampered = dict(envelope)
                tampered["payload"] = dict(envelope["payload"], event="TAMPERED")
                workload.append((f"{i}:tamper", "tamper", tampered))
                fresh_nonce = hashlib.sha256(f"{seed}:fresh:{i}".encode()).hexdigest()[:32]
                workload.append((f"{i}:honest", "honest", signed_telemetry(fresh_nonce)))
            rng.shuffle(workload)
            for trial_id, label, envelope in workload:
                start = time.perf_counter_ns()
                try:
                    verifier.verify(envelope)
                    outcome = "accepted"
                    authenticated = True
                except HardwareTransportError as exc:
                    outcome = exc.reason
                    authenticated = exc.authenticated
                elapsed = time.perf_counter_ns() - start
                rows.append(dict(seed=seed, trial_id=trial_id, ground_truth=label,
                                 outcome=outcome, authenticated=int(authenticated),
                                 latency_ns=elapsed))
        finally:
            store.close()
    expected = {"honest": "accepted", "replay": "HW_REPLAY_NONCE_REUSED",
                "tamper": "HW_ENVELOPE_MAC_INVALID"}
    if any(row["outcome"] != expected[row["ground_truth"]] for row in rows):
        raise AssertionError("security expectation failed; refusing evidence export")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return dict(seed=seed, pairs=pairs, trials=len(rows),
                median_latency_ns=statistics.median(r["latency_ns"] for r in rows),
                csv=str(output), limitation="component-only; no TCP or physical validation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--pairs", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.seed, args.pairs, args.output), sort_keys=True))
