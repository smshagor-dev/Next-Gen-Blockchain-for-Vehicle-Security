"""Independent cold/warm SQLite admission latency experiment (non-actuating).

Run from repository root:
  python -m research_contracts.benchmark_durable_admission --repeats 30 --output /tmp/durable.json

This is an engineering overhead benchmark, NOT V2X attack-detection evidence.
Each repetition uses a fresh SQLite file; each phase has identical evidence.
"""
import argparse
import json
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path

from .durable_epoch_admission import DurableEpochAdmission
from .epoch_admission_controls import EpochAdmission, Evidence


def observation(sender):
    return Evidence(incident="benchmark-hazard", sender=sender, epoch=0,
                    nonce="nonce-" + sender, event="hazard", verified=True)


def trial(root, index):
    path = str(root / ("trial-%04d.sqlite" % index))
    begin = time.perf_counter_ns()
    durable = DurableEpochAdmission(path, quorum=2)
    cold_ns = time.perf_counter_ns() - begin
    memory = EpochAdmission(quorum=2)
    samples = {}
    for name, gate in (("memory", memory), ("sqlite", durable)):
        durations = []
        outcomes = []
        for sender in ("peer-a", "peer-b", "peer-c"):
            start = time.perf_counter_ns()
            outcomes.append(gate.admit(observation(sender)))
            durations.append(time.perf_counter_ns() - start)
        if outcomes != [False, True, False]:
            raise AssertionError("unexpected admission outcome: " + repr((name, outcomes)))
        samples[name] = durations
    restarted = DurableEpochAdmission(path, quorum=2)
    if restarted.admit(observation("peer-d")) is not False:
        raise AssertionError("restart emitted duplicate authorization")
    return {"cold_start_ns": cold_ns, "memory_ns": samples["memory"],
            "sqlite_ns": samples["sqlite"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 2 <= args.repeats <= 10000:
        parser.error("--repeats must be between 2 and 10000")
    output = Path(args.output)
    if output.exists():
        parser.error("refusing to overwrite an existing evidence file")
    with tempfile.TemporaryDirectory() as folder:
        results = [trial(Path(folder), i) for i in range(args.repeats)]
    payload = {
        "schema": 1, "purpose": "non-publishable engineering microbenchmark",
        "platform": platform.platform(), "python": platform.python_version(),
        "pid": os.getpid(), "clock": "perf_counter_ns",
        "repeats": args.repeats, "samples": results,
        "limitations": ["Sequential same-process measurements, not randomized order",
                        "No network, ECU, physical interlock, or attack-detection evaluation",
                        "No inference of significance from repetition count"],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    print("Recorded", args.repeats, "paired trials to", output)
    print("Median cold start (ms):",
          round(statistics.median(x["cold_start_ns"] for x in results) / 1e6, 3))


if __name__ == "__main__":
    main()
