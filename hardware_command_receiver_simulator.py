"""Simulation-only authenticated command receiver; never actuates hardware.

The durable claim is atomic across SQLite connections and survives process restart
when the database is preserved. It does not protect against storage rollback,
key compromise, or a compromised enrolled sender.
"""
from __future__ import annotations

import sqlite3
import re
from contextlib import closing
from pathlib import Path
from typing import Any, Mapping

from hardware_transport_security import HardwareEnvelopeVerifier, HardwareTransportError
from command_ack_protocol import issue_receipt


class DurableCommandNonceStore:
    def __init__(self, path: str):
        if not path or path == ":memory:":
            raise ValueError("persistent SQLite path required")
        self.path = str(Path(path).resolve())
        with closing(self._connect()) as db:
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
        with closing(self._connect()) as db:
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

    def receive(
        self, frame: Any, *, expected_device_id: str,
        requester_challenge: str | None = None,
    ) -> dict[str, object]:
        # A caller's fresh challenge is passed over an assumed trusted
        # requester/receiver channel. It is not part of the COMMAND MAC:
        # this module is a non-actuating simulator, not a production wire ACK.
        # Validate before claiming a durable nonce so malformed requests do
        # not consume one-time admissions.
        if requester_challenge is not None:
            if (type(requester_challenge) is not str
                    or not re.fullmatch(r"[a-f0-9]{32,128}", requester_challenge)
                    or len(requester_challenge) % 2):
                raise HardwareTransportError("HW_REQUESTER_CHALLENGE_INVALID")
        verified = self.verifier.verify(
            frame, expected_kind="COMMAND", expected_device_id=expected_device_id
        )
        try:
            claimed = self.store.claim(verified.device_id, verified.nonce, verified.timestamp)
        except sqlite3.Error as exc:
            raise HardwareTransportError("HW_DURABLE_REPLAY_STORAGE_UNAVAILABLE", authenticated=True) from exc
        if not claimed:
            raise HardwareTransportError("HW_DURABLE_COMMAND_REPLAY", authenticated=True)
        result: dict[str, object] = {
            "status": "SIMULATED_ADMISSION_ONLY",
            "device_id": verified.device_id,
            "nonce": verified.nonce,
            "actuation_performed": False,
            "physical_acknowledgment": False,
        }
        if requester_challenge is not None:
            # Sign only after the replay-resistant SQLite transaction has
            # committed. Lost/duplicated acknowledgments cannot repeat a
            # command and never imply physical command execution.
            result["admission_receipt"] = issue_receipt(
                self.verifier.device_secret(verified.device_id),
                device_id=verified.device_id,
                command_nonce=verified.nonce,
                challenge=requester_challenge,
                admitted=True,
            )
        return result
