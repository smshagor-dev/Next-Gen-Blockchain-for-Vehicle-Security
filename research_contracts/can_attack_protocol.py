"""Deterministic offline classic-CAN attack injection; never opens vehicle interfaces.
Labels indicate synthetic transformations, not independently verified attacks.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import random

@dataclass(frozen=True)
class Frame:
    timestamp_ns: int
    arbitration_id: int
    payload_hex: str

    def __post_init__(self):
        if type(self.timestamp_ns) is not int or self.timestamp_ns < 0:
            raise ValueError("invalid timestamp")
        if type(self.arbitration_id) is not int or not 0 <= self.arbitration_id <= 0x1FFFFFFF:
            raise ValueError("invalid arbitration ID")
        if type(self.payload_hex) is not str or len(self.payload_hex) % 2 or len(self.payload_hex) > 16:
            raise ValueError("invalid classic CAN payload length")
        try:
            bytes.fromhex(self.payload_hex)
        except ValueError as exc:
            raise ValueError("invalid CAN payload") from exc
        if self.payload_hex != self.payload_hex.upper():
            raise ValueError("payload must be canonical uppercase hex")

def generate_scenario(frames, *, seed, mode, attack_fraction=0.2):
    """Replay earlier data, spoof an identifier, or flip one payload bit offline."""
    if type(seed) is not int or type(attack_fraction) is not float or not 0 < attack_fraction <= 1:
        raise ValueError("invalid experiment parameters")
    if mode not in ("replay", "spoof", "false_data"):
        raise ValueError("unsupported attack")
    frames = tuple(frames)
    if not frames or any(type(f) is not Frame for f in frames):
        raise ValueError("nonempty Frame input required")
    if any(a.timestamp_ns >= b.timestamp_ns for a,b in zip(frames, frames[1:])):
        raise ValueError("strictly increasing source timestamps required")
    rng = random.Random(seed)
    count = max(1, int(len(frames) * attack_fraction))
    eligible = [i for i,f in enumerate(frames) if mode != "false_data" or f.payload_hex]
    if not eligible:
        raise ValueError("no eligible frames")
    chosen = set(rng.sample(eligible, min(count, len(eligible))))
    output = []
    for i, frame in enumerate(frames):
        payload, can_id = frame.payload_hex, frame.arbitration_id
        if i in chosen:
            if mode == "replay":
                source = frames[rng.randrange(i + 1)]
                payload, can_id = source.payload_hex, source.arbitration_id
            elif mode == "spoof":
                can_id = (can_id + 1) & 0x1FFFFFFF
            else:
                raw = bytearray.fromhex(payload)
                raw[0] ^= 1
                payload = raw.hex().upper()
        output.append({"timestamp_ns":frame.timestamp_ns,"arbitration_id":can_id,
                       "payload_hex":payload,"injected":i in chosen,"source_index":i})
    canonical = json.dumps(output, sort_keys=True, separators=(",", ":")).encode()
    return {"mode":mode,"seed":seed,"source_count":len(frames),
            "injected_count":len(chosen),"trace_sha256":sha256(canonical).hexdigest(),
            "records":output,"ground_truth":"synthetic_injection_only"}
