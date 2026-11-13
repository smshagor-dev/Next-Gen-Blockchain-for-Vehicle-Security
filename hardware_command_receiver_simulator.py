"""Simulation-only authenticated command receiver; never actuates hardware.

The durable claim is atomic across SQLite connections and survives process restart
when the database is preserved. It does not protect against storage rollback,
key compromise, or a compromised enrolled sender.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Mapping

from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError


class DurableCommandNonceStore:
    def __init__(self, path: str):
        if not path or path == ":memory:":
            raise ValueError("persistent SQLite path required")
        self.path = str(Path(path).resolve())
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS accepted_commands (
                device_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                PRIMARY KEY (device_id, nonce)
            )""")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def claim(self, device_id: str, nonce: str, accepted_at: str) -> bool:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO accepted_commands(device_id,nonce,accepted_at) VALUES(?,?,?)",
                    (device_id, nonce, accepted_at),
                )
                db.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                db.execute("ROLLBACK")
                return False
            except BaseException:
                db.execute("ROLLBACK")
                raise


class SimulatedCommandReceiver:
    """Verify signed stop request, durably claim nonce, record simulation outcome.

    This component intentionally has no GPIO, CAN, serial, or actuator access.
    ACK describes simulator admission only, not physical command execution.
    """
    def __init__(self, device_keys: Mapping[str, str], database_path: str):
        self.verifier = HardwareEnvelopeVerifier(device_keys)
        self.store = DurableCommandNonceStore(database_path)

    def receive(self, frame: Any, *, expected_device_id: str) -> dict[str, object]:
        verified = self.verifier.verify(
            frame, expected_kind="COMMAND", expected_device_id=expected_device_id
        )
        try:
            claimed = self.store.claim(verified.device_id, verified.nonce, verified.timestamp)
        except sqlite3.Error as exc:
            raise HardwareTransportError("HW_DURABLE_REPLAY_STORAGE_UNAVAILABLE", authenticated=True) from exc
        if not claimed:
            raise HardwareTransportError("HW_DURABLE_COMMAND_REPLAY", authenticated=True)
        return {
            "status": "SIMULATED_ADMISSION_ONLY",
            "device_id": verified.device_id,
            "nonce": verified.nonce,
            "actuation_performed": False,
            "physical_acknowledgment": False,
        }
