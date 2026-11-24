"""Non-actuating bounded authenticated ingress reference, not a production hardware bridge."""
import hashlib
import hmac
import json
import sqlite3
import time

MAX_FRAME = 4096
MAX_AGE_SECONDS = 5

class Reject(ValueError):
    pass

def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def frame(payload, key):
    raw = canonical(payload)
    mac = hmac.new(key, raw, hashlib.sha256).hexdigest()
    return canonical({'payload': payload, 'mac': mac}) + b'\n'

class EvidenceOnlyGate:
    def __init__(self, path, keys, clock=time.time):
        self.db = sqlite3.connect(path, isolation_level=None, timeout=2)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS seen (device TEXT NOT NULL, nonce TEXT NOT NULL, PRIMARY KEY(device,nonce))')
        self.keys, self.clock = keys, clock

    def ingest(self, raw):
        if not isinstance(raw, bytes) or len(raw) > MAX_FRAME or not raw.endswith(b'\n'):
            raise Reject('bounded newline frame required')
        try:
            msg = json.loads(raw[:-1]); p = msg['payload']; mac = msg['mac']
            if set(msg) != {'payload', 'mac'} or not isinstance(p, dict) or set(p) != {'device','nonce','timestamp','observation'}:
                raise Reject('schema')
            device, nonce = p['device'], p['nonce']
            if not isinstance(device,str) or not isinstance(nonce,str) or not (1 <= len(nonce) <= 64):
                raise Reject('identity')
            if device not in self.keys or not isinstance(mac,str) or len(mac) != 64:
                raise Reject('authentication')
            expected = hmac.new(self.keys[device], canonical(p), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, mac):
                raise Reject('authentication')
            ts = p['timestamp']
            if isinstance(ts,bool) or not isinstance(ts,(int,float)) or abs(self.clock()-ts) > MAX_AGE_SECONDS:
                raise Reject('stale')
            if not isinstance(p['observation'], dict):
                raise Reject('observation')
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            raise Reject('invalid frame') from exc
        try:
            self.db.execute('INSERT INTO seen(device,nonce) VALUES (?,?)', (device,nonce))
        except sqlite3.IntegrityError as exc:
            raise Reject('replay') from exc
        return {'status':'evidence_only', 'device':device, 'nonce':nonce}
