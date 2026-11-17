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
MAX_SESSION_FRAMES = 256  # Bound authenticated event and durable-storage work per session.

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
    def __init__(self, keys, limit=MAX_FRAME, replay_gate=None, session_byte_limit=MAX_SESSION_BYTES, session_frame_limit=MAX_SESSION_FRAMES):
        if not 1 <= limit <= MAX_FRAME:
            raise ValueError("invalid limit")
        if type(session_byte_limit) is not int or not MAX_FRAME <= session_byte_limit <= MAX_SESSION_BYTES:
            raise ValueError("invalid session byte limit")
        if type(session_frame_limit) is not int or not 1 <= session_frame_limit <= MAX_SESSION_FRAMES:
            raise ValueError("invalid session frame limit")
        self.session_frame_limit = session_frame_limit
        self.accepted_frames = 0
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
        # Preflight fully buffered frame count before any replay-store mutation.
        # This prevents a known over-budget batch from consuming a durable nonce
        # and then returning no events. Invalid later frames can still leave
        # earlier commits; this is NOT general batch atomicity.
        probe = bytes(self.buffer)  # Preserve partial header OR body across feed calls.
        probe_expected = self.expected
        cursor = 0
        complete = 0
        completed_payloads = []
        while cursor < len(chunk):
            if probe_expected is None:
                needed = 4 - len(probe)
                probe += chunk[cursor:cursor + needed]
                cursor += min(needed, len(chunk) - cursor)
                if len(probe) < 4:
                    break
                probe_expected = int.from_bytes(probe, "big")
                probe = b""
                if not 1 <= probe_expected <= self.limit:
                    self.poisoned = True
                    self.buffer.clear()
                    self.expected = None
                    raise FrameError("frame size rejected")
            needed = probe_expected - len(probe)
            take = min(needed, len(chunk) - cursor)
            probe += chunk[cursor:cursor + take]
            cursor += take
            if len(probe) == probe_expected:
                completed_payloads.append(probe)
                complete += 1
                probe = b""
                probe_expected = None
        if complete > self.session_frame_limit - self.accepted_frames:
            self.poisoned = True
            self.buffer.clear()
            self.expected = None
            raise FrameError("session frame budget exhausted before admission")
        # Preflight syntax for every complete frame before committing any replay
        # sequence. This is deliberately NOT a transaction across valid frames:
        # a later authenticated replay/storage failure may still follow a commit.
        try:
            for candidate in completed_payloads:
                json.loads(candidate, object_pairs_hook=_unique_object,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON constant")))
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            self.poisoned = True
            self.buffer.clear()
            self.expected = None
            raise FrameError("batch syntax preflight rejected") from exc
        # Authentication preflight prevents a later bad-MAC frame from consuming
        # an earlier frame's durable replay sequence in the same transport batch.
        # Storage rejection after preflight remains non-atomic; see status matrix.
        try:
            for candidate in completed_payloads:
                envelope = json.loads(candidate, object_pairs_hook=_unique_object,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON constant")))
                if not isinstance(envelope, dict) or set(envelope) != {"node", "seq", "event", "mac"}:
                    raise ValueError("unexpected envelope fields")
                node, seq, event, mac = (envelope[k] for k in ("node", "seq", "event", "mac"))
                if (not isinstance(node, str) or node not in self.keys or
                    type(seq) is not int or not 0 <= seq <= 9223372036854775807 or
                    not isinstance(event, dict) or not isinstance(mac, str)):
                    raise ValueError("invalid authenticated envelope")
                canonical = json.dumps({"node": node, "seq": seq, "event": event},
                    sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                expected_mac = hmac.new(self.keys[node], canonical, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected_mac, mac):
                    raise ValueError("invalid MAC")
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            self.poisoned = True
            self.buffer.clear()
            self.expected = None
            raise FrameError("batch authentication preflight rejected") from exc
        # Detect within-batch replay/order violations before any durable write.
        # This does not make external storage admission transactional.
        batch_highwater = dict(self.seen)
        try:
            for candidate in completed_payloads:
                envelope = json.loads(candidate, object_pairs_hook=_unique_object)
                node, seq = envelope["node"], envelope["seq"]
                if seq <= batch_highwater.get(node, -1):
                    raise ValueError("non-increasing sequence within batch")
                batch_highwater[node] = seq
        except (ValueError, TypeError, KeyError) as exc:
            self.poisoned = True
            self.buffer.clear()
            self.expected = None
            raise FrameError("batch replay-order preflight rejected") from exc
        # Atomic durable replay admission for all complete authenticated frames
        # in this feed call. No event is exposed until the entire transaction
        # commits. The legacy single-entry gate remains non-atomic and is not
        # suitable for multi-frame production admission.
        batch_committed = False
        if completed_payloads and self.replay_gate is not None:
            batch_method = getattr(self.replay_gate, "admit_authenticated_batch", None)
            if batch_method is not None:
                try:
                    entries = []
                    for candidate in completed_payloads:
                        envelope = json.loads(candidate, object_pairs_hook=_unique_object)
                        entries.append((envelope["node"], envelope["seq"]))
                    if not batch_method(entries, authenticated=True):
                        raise FrameError("durable batch replay rejected")
                    batch_committed = True
                except Exception as exc:
                    self.poisoned = True
                    self.buffer.clear()
                    self.expected = None
                    raise FrameError("durable batch admission failed") from exc
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
                    # Bound expensive MAC verification and durable replay commits,
                    # independently of the cumulative byte budget.
                    if self.accepted_frames >= self.session_frame_limit:
                        raise FrameError("session frame budget exhausted")
                    item = self._admit(payload, replay_checked=batch_committed)
                    self.accepted_frames += 1
                    accepted.append(item)
                except Exception as exc:  # Storage errors must also terminate this connection.
                    self.poisoned = True
                    raise FrameError("connection rejected after invalid frame") from exc
        return accepted

    def _admit(self, payload, replay_checked=False):
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
            if self.replay_gate is not None and not replay_checked:
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

    def test_fragmented_body_followed_by_next_frame(self):
        # A partial body followed by a second complete frame must not cause
        # the preflight scanner to misinterpret body bytes as a new header.
        first = frame("a", 1, {"hazard": True}, b"secret-a")
        second = frame("a", 2, {}, b"secret-a")
        cut = 12
        self.assertEqual(self.receiver.feed(first[:cut]), [])
        self.assertEqual([item["seq"] for item in self.receiver.feed(first[cut:] + second)], [1, 2])

    def test_fragmented_body_budget_preflight_no_partial_commit(self):
        first = frame("a", 1, {"hazard": True}, b"secret-a")
        second = frame("a", 2, {}, b"secret-a")
        receiver = BoundedReceiver({"a": b"secret-a"}, session_frame_limit=1)
        self.assertEqual(receiver.feed(first[:12]), [])
        with self.assertRaises(FrameError):
            receiver.feed(first[12:] + second)
        self.assertEqual(receiver.accepted_frames, 0)
        self.assertEqual(receiver.seen, {})
        self.assertTrue(receiver.poisoned)

    def test_bad_mac_second_frame_does_not_consume_first_nonce(self):
        class RecordingGate:
            def __init__(self):
                self.calls = []
            def admit_authenticated(self, node, seq, authenticated=False):
                self.calls.append((node, seq))
                return True
        gate = RecordingGate()
        receiver = BoundedReceiver({"a": b"secret-a"}, replay_gate=gate)
        valid = frame("a", 1, {}, b"secret-a")
        bad_mac = frame("a", 2, {}, b"wrong-key")
        with self.assertRaises(FrameError):
            receiver.feed(valid + bad_mac)
        self.assertEqual(gate.calls, [])
        self.assertEqual(receiver.accepted_frames, 0)
        self.assertTrue(receiver.poisoned)

    def test_bad_mac_second_frame_after_fragmented_first(self):
        receiver = BoundedReceiver({"a": b"secret-a"})
        first = frame("a", 1, {"hazard": True}, b"secret-a")
        self.assertEqual(receiver.feed(first[:13]), [])
        with self.assertRaises(FrameError):
            receiver.feed(first[13:] + frame("a", 2, {}, b"wrong-key"))
        self.assertEqual(receiver.seen, {})
        self.assertTrue(receiver.poisoned)

    def test_malformed_second_frame_does_not_consume_first_nonce(self):
        class RecordingGate:
            def __init__(self):
                self.calls = []
            def admit_authenticated(self, node, seq, authenticated=False):
                self.calls.append((node, seq))
                return True
        gate = RecordingGate()
        receiver = BoundedReceiver({"a": b"secret-a"}, replay_gate=gate)
        malformed = b'{"node":'
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 1, {}, b"secret-a") + len(malformed).to_bytes(4, "big") + malformed)
        self.assertEqual(gate.calls, [])
        self.assertTrue(receiver.poisoned)

    def test_duplicate_key_in_second_frame_does_not_consume_first_nonce(self):
        receiver = BoundedReceiver({"a": b"secret-a"})
        malformed = b'{"node":"a","node":"a"}'
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 1, {}, b"secret-a") + len(malformed).to_bytes(4, "big") + malformed)
        self.assertEqual(receiver.seen, {})

    def test_duplicate_sequence_in_coalesced_batch_never_calls_gate(self):
        class RecordingGate:
            def __init__(self):
                self.calls = []
            def admit_authenticated(self, node, seq, authenticated=False):
                self.calls.append((node, seq))
                return True
        gate = RecordingGate()
        receiver = BoundedReceiver({"a": b"secret-a"}, replay_gate=gate)
        duplicate = frame("a", 7, {}, b"secret-a")
        with self.assertRaises(FrameError):
            receiver.feed(duplicate + duplicate)
        self.assertEqual(gate.calls, [])
        self.assertEqual(receiver.accepted_frames, 0)
        self.assertTrue(receiver.poisoned)

    def test_decreasing_sequence_in_batch_rejected_before_mutation(self):
        receiver = BoundedReceiver({"a": b"secret-a"})
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 8, {}, b"secret-a") + frame("a", 7, {}, b"secret-a"))
        self.assertEqual(receiver.seen, {})
        self.assertTrue(receiver.poisoned)

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
        seq = 1
        while True:
            payload = frame("a", seq, {}, b"secret-a")
            if receiver.received_bytes + len(payload) > MAX_FRAME:
                break
            for byte in payload:
                receiver.feed(bytes([byte]))
            seq += 1
        remaining = MAX_FRAME - receiver.received_bytes
        for byte in payload[:remaining]:
            receiver.feed(bytes([byte]))
        self.assertEqual(receiver.received_bytes, MAX_FRAME)
        with self.assertRaises(FrameError):
            receiver.feed(bytes([payload[remaining]]))
        self.assertTrue(receiver.poisoned)

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

    def test_authenticated_frame_count_budget(self):
        receiver = BoundedReceiver({"a": b"secret-a"}, session_frame_limit=2)
        self.assertEqual([x["seq"] for x in receiver.feed(frame("a", 1, {}, b"secret-a") + frame("a", 2, {}, b"secret-a"))], [1, 2])
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 3, {}, b"secret-a"))
        self.assertTrue(receiver.poisoned)
        self.assertEqual(receiver.accepted_frames, 2)

    def test_batch_cannot_bypass_frame_count_budget(self):
        receiver = BoundedReceiver({"a": b"secret-a"}, session_frame_limit=1)
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 1, {}, b"secret-a") + frame("a", 2, {}, b"secret-a"))
        self.assertTrue(receiver.poisoned)
        self.assertEqual(receiver.accepted_frames, 0)
        self.assertNotIn("a", receiver.seen)
        # The rejected batch did not consume a replay sequence.

    def test_over_budget_batch_does_not_call_durable_store(self):
        class RecordingGate:
            def __init__(self):
                self.calls = []
            def admit_authenticated(self, node, seq, authenticated=False):
                self.calls.append((node, seq))
                return True
        gate = RecordingGate()
        receiver = BoundedReceiver({"a": b"secret-a"}, replay_gate=gate, session_frame_limit=1)
        with self.assertRaises(FrameError):
            receiver.feed(frame("a", 1, {}, b"secret-a") + frame("a", 2, {}, b"secret-a"))
        self.assertEqual(gate.calls, [])
        self.assertTrue(receiver.poisoned)

    def test_invalid_frame_count_configuration(self):
        for limit in (0, -1, True, MAX_SESSION_FRAMES + 1):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                BoundedReceiver({"a": b"secret-a"}, session_frame_limit=limit)

    def test_no_actuator_interface(self):
        self.assertFalse(hasattr(self.receiver, "actuate"))

if __name__ == "__main__":
    unittest.main()
