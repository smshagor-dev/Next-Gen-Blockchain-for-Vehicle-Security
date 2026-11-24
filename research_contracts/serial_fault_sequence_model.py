"""Non-actuating serial fault-sequence model for controlled research.

This is a reference state machine, not a replacement for hardware_bridge.
All inputs are synthetic and results are not publication-ready.
"""
from dataclasses import dataclass
from enum import Enum
import argparse
import json
import random

class State(str, Enum):
    OPEN = "open"
    QUARANTINED = "quarantined"

@dataclass
class Session:
    byte_limit: int = 4096
    frame_limit: int = 8
    state: State = State.OPEN
    bytes_seen: int = 0
    frames_seen: int = 0
    accepted: int = 0
    rejected: int = 0
    quarantine_reason: str = ""

    def step(self, *, bytes_received: int, frame_complete: bool = False,
             authenticated: bool = False, malformed: bool = False):
        """Account before verification; never dispatch actuator commands."""
        if self.state != State.OPEN:
            return "closed"
        if type(bytes_received) is not int or bytes_received < 0:
            raise ValueError("nonnegative integer byte count required")
        self.bytes_seen += bytes_received
        if self.bytes_seen > self.byte_limit:
            return self._quarantine("byte_budget")
        if malformed:
            return self._quarantine("malformed")
        if frame_complete:
            self.frames_seen += 1
            if self.frames_seen > self.frame_limit:
                return self._quarantine("frame_budget")
            if not authenticated:
                return self._quarantine("authentication")
            self.accepted += 1
            return "evidence_only"
        return "incomplete"

    def _quarantine(self, reason):
        self.state = State.QUARANTINED
        self.quarantine_reason = reason
        self.rejected += 1
        return "quarantined"

def run(seed: int, sequences: int = 1000):
    """Paired synthetic workload with predeclared attack labels.

    This measures model invariants, not production performance or accuracy.
    """
    rng = random.Random(seed)
    results = []
    for i in range(sequences):
        kind = ("valid", "partial_flood", "bad_mac", "malformed",
                "frame_flood", "valid_then_bad")[i % 6]
        s = Session(byte_limit=256, frame_limit=3)
        if kind == "valid":
            s.step(bytes_received=32, frame_complete=True, authenticated=True)
        elif kind == "partial_flood":
            for _ in range(17):
                s.step(bytes_received=16)
        elif kind == "bad_mac":
            s.step(bytes_received=32, frame_complete=True)
        elif kind == "malformed":
            s.step(bytes_received=32, malformed=True)
        elif kind == "frame_flood":
            for _ in range(4):
                s.step(bytes_received=32, frame_complete=True, authenticated=True)
        else:
            s.step(bytes_received=32, frame_complete=True, authenticated=True)
            s.step(bytes_received=32, frame_complete=True)
        # Randomize harmless post-quarantine bytes; quarantine must be absorbing.
        if s.state == State.QUARANTINED:
            previous = (s.accepted, s.frames_seen, s.bytes_seen)
            s.step(bytes_received=rng.randrange(1, 64),
                   frame_complete=True, authenticated=True)
            assert previous == (s.accepted, s.frames_seen, s.bytes_seen)
        results.append({"scenario": kind, "accepted": s.accepted,
                        "state": s.state.value, "reason": s.quarantine_reason})
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--sequences", type=int, default=1000)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 1 <= args.sequences <= 100000:
        parser.error("sequences must be between 1 and 100000")
    results = run(args.seed, args.sequences)
    with open(args.output, "w", encoding="utf-8") as f:
        for item in results:
            f.write(json.dumps(item, sort_keys=True) + "\n")
    print(json.dumps({"seed": args.seed, "sequences": len(results),
                      "quarantined": sum(x["state"] == "quarantined" for x in results),
                      "note": "synthetic reference-state-machine evidence only"}))

if __name__ == "__main__":
    main()
