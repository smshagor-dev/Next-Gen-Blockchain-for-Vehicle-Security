"""Simulation-only receiver framing model. Never drives a vehicle actuator.

Run: python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v
"""
import hashlib
import hmac
import json
import unittest

MAX_FRAME = 4096
MAX_CHUNK = 16384  # Bound work per feed call; transport must split larger reads.
MAX_SESSION_BYTES = 262144  # Bound cumulative connection work, including incomplete bytes.

class FrameError(ValueError):
    pass

def _unique_object(pairs):
    """Reject duplicate keys at every nesting depth before authentication."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


class BoundedReceiver:
    """Length-prefixed frames; authenticate before admitting an event.

    Replay state is intentionally volatile: reboot durability is NOT claimed.
    """
    def __init__(self, keys, limit=MAX_FRAME, replay_gate=None, session_byte_limit=MAX_SESSION_BYTES):
        if not 1 <= limit <= MAX_FRAME:
            raise ValueError("invalid limit")
        if type(session_byte_limit) is not int or not MAX_FRAME <= session_byte_limit <= MAX_SESSION_BYTES:
            raise ValueError("invalid session byte limit")
        self.session_byte_limit = session_byte_limit
        self.received_bytes = 0
        self.keys = dict(keys)
        self.limit = limit
        self.buffer = bytearray()
        self.expected = None
        self.seen = {}
        self.replay_gate = replay_gate
        self.poisoned = False  # A rejected frame terminates this simulated connection.

    def feed(self, chunk):
        if self.poisoned:
            raise FrameError("connection rejected; create a new receiver")
        if not isinstance(chunk, bytes):
            raise TypeError("bytes required")
        if len(chunk) > MAX_CHUNK:
            self.poisoned = True
            raise FrameError("oversized transport chunk")
        # Charge bytes before parsing: tiny fragments cannot evade the budget.
        if len(chunk) > self.session_byte_limit - self.received_bytes:
            self.poisoned = True
            self.buffer.clear()
            self.expected = None
            raise FrameError("session byte budget exhausted")
        self.received_bytes += len(chunk)
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
                    self.poisoned = True
                    raise FrameError("frame size rejected")
            need = self.expected - len(self.buffer)
            take = min(need, len(chunk) - offset)
            self.buffer.extend(chunk[offset:offset + take])
            offset += take
            if len(self.buffer) == self.expected:
                payload = bytes(self.buffer)
                self.buffer.clear()
                self.expected = None
                try:
                    accepted.append(self._admit(payload))
                except Exception as exc:  # Storage errors must also terminate this connection.
                    self.poisoned = True
                    raise FrameError("connection rejected after invalid frame") from exc
        return accepted

    def _admit(self, payload):
        try:
            envelope = json.loads(payload, object_pairs_hook=_unique_object)
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
            if seq > 9223372036854775807:
                raise ValueError("sequence exceeds durable store range")
            if self.replay_gate is not None:
                # Commit authenticated high-water mark before exposing admission.
                # Storage failures propagate: no event is returned to the caller.
                if not self.replay_gate.admit_authenticated(node, seq, authenticated=True):
                    raise ValueError("replay or durable gate rejection")
            else:
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
            self.receiver.feed(bytes(4))

    def test_transport_chunk_budget(self):
        with self.assertRaises(FrameError):
            self.receiver.feed(b"x" * (MAX_CHUNK + 1))
        self.assertEqual(self.receiver.buffer, bytearray())
        with self.assertRaises(FrameError):
            self.receiver.feed(frame("a", 1, {}, b"secret-a"))
        self.assertEqual(BoundedReceiver({"a": b"secret-a"}).feed(frame("a", 1, {}, b"secret-a"))[0]["seq"], 1)

    def test_duplicate_top_level_key_rejected(self):
        raw = b'{"node":"a","node":"a","seq":1,"event":{},"mac":"bad"}'
        with self.assertRaises(FrameError):
            self.receiver.feed(len(raw).to_bytes(4, "big") + raw)

    def test_duplicate_nested_event_key_rejected(self):
        raw = b'{"node":"a","seq":1,"event":{"hazard":false,"hazard":true},"mac":"bad"}'
        with self.assertRaises(FrameError):
            self.receiver.feed(len(raw).to_bytes(4, "big") + raw)

    def test_tamper_poison_prevents_reuse_of_same_connection(self):
        with self.assertRaises(FrameError):
            self.receiver.feed(frame("a", 1, {}, b"wrong"))
        with self.assertRaises(FrameError):
            self.receiver.feed(frame("a", 2, {}, b"secret-a"))
        self.assertTrue(self.receiver.poisoned)

    def test_invalid_header_poison_prevents_reuse(self):
        with self.assertRaises(FrameError):
            self.receiver.feed((MAX_FRAME + 1).to_bytes(4, "big"))
        with self.assertRaises(FrameError):
            self.receiver.feed(frame("a", 1, {}, b"secret-a"))

    def test_nested_json_depth_fails_closed(self):
        nested = '[' * 1200 + '0' + ']' * 1200
        raw = ('{"node":"a","seq":1,"event":{"nested":' + nested + '},"mac":"bad"}').encode()
        with self.assertRaises(FrameError):
            self.receiver.feed(len(raw).to_bytes(4, "big") + raw)
        self.assertTrue(self.receiver.poisoned)

    def test_durable_store_failure_poison_connection(self):
        class FailedStore:
            def admit_authenticated(self, node, seq, authenticated=False):
                raise OSError("injected storage failure")
        receiver = BoundedReceiver({"a": b"secret-a"}, replay_gate=FailedStore())
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 1, {}, b"secret-a"))
        self.assertTrue(receiver.poisoned)
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 2, {}, b"secret-a"))

    def test_durable_store_rejection_poison_connection(self):
        class RejectedStore:
            def admit_authenticated(self, node, seq, authenticated=False):
                return False
        receiver = BoundedReceiver({"a": b"secret-a"}, replay_gate=RejectedStore())
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 1, {}, b"secret-a"))
        self.assertTrue(receiver.poisoned)

    def test_fragmented_trickle_cannot_bypass_cumulative_budget(self):
        receiver = BoundedReceiver({"a": b"secret-a"}, session_byte_limit=MAX_FRAME)
        for _ in range(MAX_FRAME):
            receiver.feed(b"\\x00")
        with self.assertRaises(FrameError):
            receiver.feed(b"\\x00")
        self.assertTrue(receiver.poisoned)
        self.assertEqual(receiver.received_bytes, MAX_FRAME)

    def test_valid_frames_also_consume_session_budget(self):
        receiver = BoundedReceiver({"a": b"secret-a"}, session_byte_limit=MAX_FRAME)
        for seq in range(1, 5):
            receiver.feed(frame("a", seq, {}, b"secret-a"))
        with self.assertRaises(FrameError):
            receiver.feed(b"x" * MAX_FRAME)
        self.assertTrue(receiver.poisoned)

    def test_session_limit_configuration_fails_closed(self):
        for limit in (0, -1, True, MAX_FRAME - 1, MAX_SESSION_BYTES + 1):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                BoundedReceiver({"a": b"secret-a"}, session_byte_limit=limit)

    def test_no_actuator_interface(self):
        self.assertFalse(hasattr(self.receiver, "actuate"))

if __name__ == "__main__":
    unittest.main()
