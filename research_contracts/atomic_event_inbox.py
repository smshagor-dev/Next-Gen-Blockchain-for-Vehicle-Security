"""Offline atomic nonce/event inbox prototype; NOT blockchain finality or actuator authorization.
Delivery is at-least-once. Consumers MUST deduplicate by event_id.
"""
import hashlib
import json
import os
import sqlite3

class AdmissionError(RuntimeError):
    pass

class AtomicEventInbox:
    def __init__(self, path, *, provision=False, max_events=100000):
        if type(max_events) is not int or not 1 <= max_events <= 1000000:
            raise ValueError("invalid capacity")
        if provision and os.path.exists(path):
            raise AdmissionError("refusing overwrite")
        if not provision and (not os.path.isfile(path) or os.path.getsize(path) == 0):
            raise AdmissionError("explicit provisioning required")
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None)
        self.max_events = max_events
        try:
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                raise AdmissionError("WAL unavailable")
            self.db.execute("PRAGMA synchronous=FULL")
            if provision:
                self.db.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY, device TEXT NOT NULL, nonce TEXT NOT NULL, payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0 CHECK(delivered IN (0,1)), UNIQUE(device,nonce))")
            else:
                if self.db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise AdmissionError("integrity check failed")
                columns = {r[1] for r in self.db.execute("PRAGMA table_info(events)")}
                if columns != {"event_id","device","nonce","payload","delivered"}:
                    raise AdmissionError("schema incompatible")
        except BaseException:
            self.db.close()
            raise

    def admit(self, device, nonce, event):
        if type(device) is not str or not 1 <= len(device) <= 96 or type(nonce) is not str or not 32 <= len(nonce) <= 128:
            raise ValueError("invalid device/nonce")
        canonical = json.dumps(event, sort_keys=True, separators=(",",":"), allow_nan=False)
        if len(canonical.encode()) > 65536:
            raise ValueError("event exceeds 64 KiB")
        event_id = hashlib.sha256((device+"\\0"+nonce+"\\0"+canonical).encode()).hexdigest()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self.db.execute("SELECT event_id FROM events WHERE device=? AND nonce=?", (device,nonce)).fetchone()
            if old:
                self.db.execute("ROLLBACK")
                return False,old[0]
            if self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] >= self.max_events:
                raise AdmissionError("capacity exhausted")
            self.db.execute("INSERT INTO events(event_id,device,nonce,payload) VALUES(?,?,?,?)",(event_id,device,nonce,canonical))
            self.db.execute("COMMIT")
            return True,event_id
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def pending(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid limit")
        return self.db.execute("SELECT event_id,payload FROM events WHERE delivered=0 ORDER BY rowid LIMIT ?",(limit,)).fetchall()

    def mark_delivered(self,event_id):
        self.db.execute("UPDATE events SET delivered=1 WHERE event_id=?",(event_id,))

    def close(self):
        self.db.close()
