"""Simulation-only receiver framing model. Never drives a vehicle actuator.

Run: python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v
"""
import hashlib
import hmac
import json
import unittest

MAX_FRAME = 4096

class FrameError(ValueError):
    pass

class BoundedReceiver:
    """Length-prefixed frames; authenticate before admitting an event.

    Replay state is intentionally volatile: reboot durability is NOT claimed.
    """
    def __init__(self, keys, limit=MAX_FRAME):
        if not 1 <= limit <= MAX_FRAME:
            raise ValueError("invalid limit")
        self.keys = dict(keys)
        self.limit = limit
        self.buffer = bytearray()
        self.expected = None
        self.seen = {}

    def feed(self, chunk):
        if not isinstance(chunk, bytes):
            raise TypeError("bytes required")
        accepted = []
        offset = 0
        while offset < len(chunk):
            if self.expected is None:
                need = 4 - len(self.buffer)
                take = min(need, len(chunk) - offset)
                self.buffer.extend(chunk[offset:offset + take])
                offset += take
                if len(self.buffer) < 4:
                    continue
                self.expected = int.from_bytes(self.buffer, "big")
                self.buffer.clear()
                if self.expected < 1 or self.expected > self.limit:
                    self.buffer.clear()
                    self.expected = None
                    raise FrameError("frame size rejected")
            need = self.expected - len(self.buffer)
            take = min(need, len(chunk) - offset)
            self.buffer.extend(chunk[offset:offset + take])
            offset += take
            if len(self.buffer) == self.expected:
                payload = bytes(self.buffer)
                self.buffer.clear()
                self.expected = None
                accepted.append(self._admit(payload))
        return accepted

    def _admit(self, payload):
        try:
            envelope = json.loads(payload)
            if not isinstance(envelope, dict) or set(envelope) != {"node", "seq", "event", "mac"}:
                raise ValueError("unexpected fields")
            node, seq, event, mac = (envelope[k] for k in ("node", "seq", "event", "mac"))
            if not isinstance(node, str) or node not in self.keys or type(seq) is not int or seq < 0:
                raise ValueError("invalid identity or sequence")
            if not isinstance(event, dict) or not isinstance(mac, str):
                raise ValueError("invalid event or mac")
            canonical = json.dumps({"node": node, "seq": seq, "event": event},
                                   sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            expected = hmac.new(self.keys[node], canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, mac):
                raise ValueError("invalid authentication")
            if seq <= self.seen.get(node, -1):
                raise ValueError("replay")
            self.seen[node] = seq
            return {"node": node, "seq": seq, "event": event}
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise FrameError("admission rejected") from exc

def frame(node, seq, event, key):
    body = {"node": node, "seq": seq, "event": event}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    body["mac"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    raw = json.dumps(body, separators=(",", ":")).encode()
    return len(raw).to_bytes(4, "big") + raw

class ReceiverFaultTests(unittest.TestCase):
    def setUp(self):
        self.receiver = BoundedReceiver({"a": b"secret-a"})

    def test_fragmented_frame(self):
        f = frame("a", 1, {"hazard": True}, b"secret-a")
        self.assertEqual(self.receiver.feed(f[:2]), [])
        self.assertEqual(self.receiver.feed(f[2:9]), [])
        self.assertEqual(len(self.receiver.feed(f[9:])), 1)

    def test_multiple_frames(self):
        f = frame("a", 1, {}, b"secret-a") + frame("a", 2, {}, b"secret-a")
        self.assertEqual([x["seq"] for x in self.receiver.feed(f)], [1, 2])

    def test_replay(self):
        f = frame("a", 1, {}, b"secret-a")
        self.receiver.feed(f)
        with self.assertRaises(FrameError):
            self.receiver.feed(f)

    def test_tampered_mac(self):
        with self.assertRaises(FrameError):
            self.receiver.feed(frame("a", 1, {}, b"wrong"))

    def test_unknown_node(self):
        with self.assertRaises(FrameError):
            self.receiver.feed(frame("b", 1, {}, b"secret-b"))

    def test_oversized_header_fails_before_body(self):
        with self.assertRaises(FrameError):
            self.receiver.feed((MAX_FRAME + 1).to_bytes(4, "big"))
        self.assertEqual(len(self.receiver.buffer), 0)

    def test_zero_length(self):
        with self.assertRaises(FrameError):
            self.receiver.feed(b"\\x00\\x00\\x00\\x00")

    def test_no_actuator_interface(self):
        self.assertFalse(hasattr(self.receiver, "actuate"))

if __name__ == "__main__":
    unittest.main()
