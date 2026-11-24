"""Simulation-only bounded authenticated V2X event admission; no actuator output.

Wire: 4-byte big-endian length, then canonical JSON containing node_id,
sequence, issued_ms, payload and mac. HMAC-SHA256 authenticates first four.
High-water marks are VOLATILE: restart replay safety is NOT provided.
"""
import hashlib
import hmac
import json
import struct

MAX_FRAME = 4096
MAX_SKEW_MS = 5000


class Reject(ValueError):
    pass


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def encode(node_id, sequence, issued_ms, payload, key):
    fields = dict(node_id=node_id, sequence=sequence, issued_ms=issued_ms, payload=payload)
    mac = hmac.new(key, canonical(fields), hashlib.sha256).hexdigest()
    body = canonical({**fields, "mac": mac})
    if len(body) > MAX_FRAME:
        raise Reject("oversize")
    return struct.pack(">I", len(body)) + body


class Admission:
    """A simulation admission gate; does not authorize physical commands."""

    def __init__(self, keys):
        self.keys = dict(keys)
        self.high_water = {}
        self.buffer = bytearray()
        self.expected = None
        self.closed = False

    def feed(self, chunk, now_ms):
        if self.closed:
            raise Reject("closed")
        if not isinstance(chunk, bytes):
            raise Reject("bytes required")
        if len(chunk) > MAX_FRAME + 4 or len(self.buffer) + len(chunk) > MAX_FRAME + 4:
            self.closed = True
            raise Reject("buffer limit")
        self.buffer.extend(chunk)
        if self.expected is None and len(self.buffer) >= 4:
            self.expected = struct.unpack(">I", self.buffer[:4])[0]
            if not 1 <= self.expected <= MAX_FRAME:
                self.closed = True
                raise Reject("frame length")
        if self.expected is None or len(self.buffer) < self.expected + 4:
            return None
        if len(self.buffer) != self.expected + 4:
            self.closed = True
            raise Reject("multiple frames in single admission")
        body = bytes(self.buffer[4:])
        self.buffer.clear()
        self.expected = None
        try:
            record = json.loads(body.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise Reject("invalid JSON") from exc
        if not isinstance(record, dict) or set(record) != {"node_id", "sequence", "issued_ms", "payload", "mac"}:
            raise Reject("schema")
        node, seq, issued, mac = (record[k] for k in ("node_id", "sequence", "issued_ms", "mac"))
        if not isinstance(node, str) or node not in self.keys or type(seq) is not int or seq < 0 or type(issued) is not int or not isinstance(mac, str):
            raise Reject("identity or types")
        if type(now_ms) is not int or abs(now_ms - issued) > MAX_SKEW_MS:
            raise Reject("stale or future")
        fields = {k: record[k] for k in ("node_id", "sequence", "issued_ms", "payload")}
        expected_mac = hmac.new(self.keys[node], canonical(fields), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            raise Reject("authentication")
        if seq <= self.high_water.get(node, -1):
            raise Reject("replay")
        self.high_water[node] = seq
        return fields
