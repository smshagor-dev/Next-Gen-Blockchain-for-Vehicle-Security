"""SQLite-backed, non-actuating epoch-admission state for restart/crash experiments.

The caller MUST supply externally verified evidence. SQLite durability is not
a trusted epoch authority, authenticated storage, consensus, or physical safety.
"""
import json
import sqlite3

from .epoch_admission_controls import EpochAdmission


class DurableEpochAdmission:
    """Serialize state transitions across processes with BEGIN IMMEDIATE.

    Return admission only after the SQLite transaction commits. No caller may
    act on a positive decision until commit succeeds. A writable or rolled-back
    database is outside this local crash-consistency threat model.
    """

    def __init__(self, path, *, quorum=2, window=1, max_buckets=128,
                 max_nonces=1024):
        self.path = str(path)
        self.bounds = dict(quorum=quorum, window=window,
                           max_buckets=max_buckets, max_nonces=max_nonces)
        EpochAdmission(**self.bounds)  # Validate before touching storage.
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS admission_state "
                       "(id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO admission_state(id,payload) VALUES(1,?)",
                       (self._encode(EpochAdmission(**self.bounds)),))
            self._decode(db.execute(
                "SELECT payload FROM admission_state WHERE id=1").fetchone()[0])
            db.execute("COMMIT")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _encode(self, state):
        return json.dumps({
            "version": 1, "bounds": self.bounds, "epoch": state.epoch,
            "stopped": state.stopped,
            "buckets": [[list(key), sorted(senders)]
                        for key, senders in state._buckets.items()],
            "nonces": [list(key) for key in sorted(state._nonces)],
            "admitted": [list(key) for key in sorted(state._admitted)],
        }, sort_keys=True, separators=(",", ":"))

    def _decode(self, payload):
        try:
            data = json.loads(payload)
            if data["version"] != 1 or data["bounds"] != self.bounds:
                raise ValueError("state schema or bounds mismatch")
            state = EpochAdmission(**self.bounds)
            if type(data["epoch"]) is not int or data["epoch"] < 0 or type(data["stopped"]) is not bool:
                raise ValueError("invalid epoch or stop latch")
            state.epoch, state.stopped = data["epoch"], data["stopped"]
            def checked_key(raw, *, nonce=False):
                if type(raw) is not list or len(raw) != 3:
                    raise ValueError("invalid durable key")
                if any(type(raw[i]) is not str or not 0 < len(raw[i]) <= 128
                       for i in (0, 2)):
                    raise ValueError("invalid durable key string")
                if type(raw[1]) is not int or not 0 <= raw[1] <= state.epoch:
                    raise ValueError("invalid durable key epoch")
                return tuple(raw)

            if any(type(name) is not list for name in
                   (data["buckets"], data["nonces"], data["admitted"])):
                raise ValueError("invalid durable collections")
            for raw_key, senders in data["buckets"]:
                key = checked_key(raw_key)
                if (key in state._buckets or type(senders) is not list or
                        not senders or len(senders) > state.max_nonces or
                        any(type(sender) is not str or
                            not 0 < len(sender) <= 128 for sender in senders) or
                        len(senders) != len(set(senders))):
                    raise ValueError("invalid bucket")
                state._buckets[key] = set(senders)
            nonce_keys = [checked_key(x, nonce=True) for x in data["nonces"]]
            admitted_keys = [checked_key(x) for x in data["admitted"]]
            if len(nonce_keys) != len(set(nonce_keys)) or len(admitted_keys) != len(set(admitted_keys)):
                raise ValueError("duplicate durable key")
            state._nonces = set(nonce_keys)
            state._admitted = set(admitted_keys)
            if (len(state._buckets) > state.max_buckets or
                    len(state._nonces) > state.max_nonces or
                    len(state._nonces) != len(data["nonces"])):
                raise ValueError("state capacity or duplicate nonce")
            for key, senders in state._buckets.items():
                if len(key) != 3 or type(key[1]) is not int or key[1] > state.epoch or key[1] < state.epoch - state.window:
                    raise ValueError("invalid bucket epoch")
                if any(not isinstance(s, str) or not s for s in senders):
                    raise ValueError("invalid sender")
            if any(key[1] < state.epoch - state.window for key in state._admitted):
                raise ValueError("admission outside epoch window")
            if not state._admitted.issubset(set(state._buckets)):
                raise ValueError("admission without evidence bucket")
            # A persisted positive decision is valid only when the persisted
            # corroborator set actually satisfies the configured quorum.
            # Otherwise a malformed or partially rewritten snapshot could
            # resurrect a positive authorization without sufficient evidence.
            if any(len(state._buckets[key]) < state.quorum for key in state._admitted):
                raise ValueError("admission without quorum; fail closed")
            if any(len(x) != 3 or type(x[1]) is not int or x[1] > state.epoch or x[1] < state.epoch - state.window for x in state._nonces):
                raise ValueError("invalid nonce epoch")
            return state
        except (KeyError, TypeError, AttributeError, IndexError, json.JSONDecodeError) as exc:
            raise ValueError("corrupt admission state; fail closed") from exc

    def _transition(self, method, *args, **kwargs):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload FROM admission_state WHERE id=1").fetchone()
            if row is None:
                raise ValueError("missing durable state; fail closed")
            state = self._decode(row[0])
            result = getattr(state, method)(*args, **kwargs)
            db.execute("UPDATE admission_state SET payload=? WHERE id=1",
                       (self._encode(state),))
            db.execute("COMMIT")
            return result

    def admit(self, evidence):
        return self._transition("admit", evidence)

    def advance_epoch(self, epoch):
        return self._transition("advance_epoch", epoch)

    def local_emergency_stop(self):
        return self._transition("local_emergency_stop")

    def local_reset(self, *, operator_confirmed=False):
        return self._transition("local_reset", operator_confirmed=operator_confirmed)
