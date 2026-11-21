"""Threat-model experiment: a malicious *enrolled* sender can sign false data.

This is a negative control, not a defense evaluation. A valid MAC proves key
possession, not physical truth. Run without hardware or network actuation.
"""
import argparse
import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import random
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hardware_nonce_store import SQLiteNonceStore
from hardware_transport_security import (
    HardwareEnvelopeVerifier, build_authenticated_envelope, _NUMERIC_RANGES, _BOOL_FIELDS,
)

DEVICE = "enrolled-bench"
SECRET = "enrolled-malicious-bench-key-0123456789abcdef0123456789"


def experiment(seed, trials, output):
    if not 0 <= seed < 2**64 or not 1 <= trials <= 100000:
        raise ValueError("invalid seed or trials")
    rng = random.Random(seed)
    labels = [i % 2 for i in range(trials)]
    rng.shuffle(labels)
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        store = SQLiteNonceStore(str(Path(directory) / "replay.db"), provision=True,
                                 max_claims=trials + 1)
        try:
            verifier = HardwareEnvelopeVerifier({DEVICE: SECRET}, durable_nonce_store=store)
            for index, falsified in enumerate(labels):
                ts = datetime.now(timezone.utc)
                values = {k: (lo + hi) / 2 for k, (lo, hi) in _NUMERIC_RANGES.items()}
                values.update({k: False for k in _BOOL_FIELDS})
                # Both values are schema-valid. Only the experiment controller
                # knows that one was deliberately fabricated.
                values["speed"] = 300.0 if falsified else 30.0
                values.update(timestamp=ts.isoformat(), event="BENCH_OBSERVATION")
                nonce = hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:32]
                envelope = build_authenticated_envelope(
                    DEVICE, SECRET, "TELEMETRY", values, timestamp=ts, nonce=nonce
                )
                accepted = verifier.verify(envelope).payload["speed"]
                rows.append(dict(seed=seed, trial=index,
                                 injected_false_data=int(falsified),
                                 accepted_by_mac_and_schema=int(accepted == values["speed"]),
                                 reported_speed=accepted))
        finally:
            store.close()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = experiment(args.seed, args.trials, args.output)
    print(f"trials={len(rows)} false_data_trials={sum(r['injected_false_data'] for r in rows)}")
