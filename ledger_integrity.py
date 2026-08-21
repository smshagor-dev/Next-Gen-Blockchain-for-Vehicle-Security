"""Versioned ledger-integrity sealing and snapshot verification for OmniGuard V2X."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

LEDGER_SEAL_VERSION = "SMARTCAR_LEDGER_SEAL_V2"
_LEDGER_SEAL_DOMAIN = (LEDGER_SEAL_VERSION + "\0").encode("utf-8")


class LedgerIntegrityError(RuntimeError):
    """Raised when an already-committed ledger view changes or fails validation."""


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def canonical_block_dict(block: Any) -> Dict[str, Any]:
    """Return the full committed block payload excluding the seal itself."""
    if hasattr(block, "to_dict") and callable(block.to_dict):
        raw = block.to_dict()
    elif isinstance(block, Mapping):
        raw = dict(block)
    else:
        raise TypeError("block must be a mapping or expose to_dict()")
    if not isinstance(raw, Mapping):
        raise TypeError("block serialization must be a mapping")
    payload = _jsonable(dict(raw))
    payload.pop("block_signature", None)
    return payload


def canonical_block_bytes(block: Any) -> bytes:
    return json.dumps(
        canonical_block_dict(block),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def block_integrity_hash(block: Any) -> str:
    return hashlib.sha3_256(canonical_block_bytes(block)).hexdigest()


def sign_block_integrity(block: Any, mac_key: bytes) -> str:
    if not isinstance(mac_key, (bytes, bytearray)) or len(mac_key) < 16:
        raise ValueError("ledger integrity MAC key must contain at least 16 bytes")
    return hmac.new(
        bytes(mac_key),
        _LEDGER_SEAL_DOMAIN + canonical_block_bytes(block),
        hashlib.sha256,
    ).hexdigest()


def seal_block_integrity(block: Any, mac_key: bytes) -> str:
    signature = sign_block_integrity(block, mac_key)
    if isinstance(block, MutableMapping):
        block["block_signature"] = signature
    else:
        setattr(block, "block_signature", signature)
    return signature


def verify_block_integrity(block: Any, mac_key: bytes) -> bool:
    if isinstance(block, Mapping):
        received = str(block.get("block_signature", ""))
    else:
        received = str(getattr(block, "block_signature", ""))
    if len(received) != 64:
        return False
    try:
        expected = sign_block_integrity(block, mac_key)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(received.lower(), expected)


def _poa_signature(block_hash: str, validator_id: str, authority_round: int, validator_key: str) -> str:
    message = f"{block_hash}|{validator_id}|{int(authority_round)}"
    return hmac.new(
        validator_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class PythonLedgerIntegrityGuard:
    """Install a fail-closed full-metadata integrity seal on one SmartCarBlockchain instance."""

    def __init__(self, core: Any):
        self.core = core
        self._original_add_block = core._add_block
        self._original_verify_chain = core.verify_chain
        self._original_create_genesis = core._create_genesis

    def install(self) -> "PythonLedgerIntegrityGuard":
        existing = getattr(self.core, "_ledger_integrity_guard_v2", None)
        if existing is not None:
            return existing
        for block in self.core.chain:
            seal_block_integrity(block, self.core.crypto.mac_key)
        self.core._add_block = self._guarded_add_block
        self.core.verify_chain = self.verify_chain
        self.core._create_genesis = self._guarded_create_genesis
        self.core._ledger_integrity_guard_v2 = self
        if not self.verify_chain():
            raise LedgerIntegrityError("initial Python ledger failed v2 integrity validation")
        return self

    def _expected_validator(self, index: int) -> str:
        return str(self.core._expected_validator(int(index)))

    def _verify_validator_signature(self, block: Any) -> bool:
        try:
            index = int(block.index)
            if int(block.authority_round) != index:
                return False
            validator_id = str(block.validator_id)
            if validator_id != self._expected_validator(index):
                return False
            validator_key = str(self.core.authority_registry.get(validator_id, ""))
            received = str(block.poa_signature)
            if not validator_key or len(received) != 64:
                return False
            expected = _poa_signature(block.block_hash, validator_id, index, validator_key)
            return hmac.compare_digest(received.lower(), expected)
        except Exception:
            return False

    def _verify_archive_reference(self, block: Any) -> bool:
        if not bool(getattr(block, "archived_pruned", False)):
            return True
        shard_id = str(getattr(block, "archive_shard_id", ""))
        root_hash = str(getattr(block, "archive_root_hash", ""))
        if not shard_id or len(root_hash) != 64:
            return False
        match: Optional[Dict[str, Any]] = None
        for meta in getattr(self.core, "archive_shards_meta", []):
            if str(meta.get("shard_id", "")) != shard_id:
                continue
            if str(meta.get("root_hash_sha3", "")) != root_hash:
                return False
            if not (
                int(meta.get("block_index_start", -1))
                <= int(block.index)
                <= int(meta.get("block_index_end", -1))
            ):
                return False
            match = meta
            break
        if match is None:
            return False
        verifier = getattr(self.core, "_verify_signed_shard_anchor", None)
        if callable(verifier):
            result = verifier(match)
            return bool(isinstance(result, dict) and result.get("valid"))
        return True

    def _verify_genesis(self) -> bool:
        if not self.core.chain:
            return False
        genesis = self.core.chain[0]
        try:
            if int(genesis.index) != 0:
                return False
            if str(genesis.vehicle_id) != str(self.core.vehicle_id):
                return False
            if str(genesis.previous_hash) != "0" * 64:
                return False
            if str(genesis.consensus) != str(self.core.consensus):
                return False
            if not self._verify_validator_signature(genesis):
                return False
            key = self.core.authority_registry.get(str(genesis.validator_id), "")
            if not key:
                return False
            if not genesis.verify(self.core.crypto, key):
                return False
            return verify_block_integrity(genesis, self.core.crypto.mac_key)
        except Exception:
            return False

    def verify_chain(self) -> bool:
        try:
            if not self._original_verify_chain():
                return False
            if not self._verify_genesis():
                return False
            previous = None
            for position, block in enumerate(self.core.chain):
                if int(block.index) != position:
                    return False
                if str(block.vehicle_id) != str(self.core.vehicle_id):
                    return False
                if previous is not None and str(block.previous_hash) != str(previous.block_hash):
                    return False
                if not self._verify_validator_signature(block):
                    return False
                if not verify_block_integrity(block, self.core.crypto.mac_key):
                    return False
                if not self._verify_archive_reference(block):
                    return False
                previous = block
            return True
        except Exception:
            return False

    def _guarded_create_genesis(self):
        result = self._original_create_genesis()
        if not self.core.chain:
            raise LedgerIntegrityError("genesis creation produced an empty chain")
        seal_block_integrity(self.core.chain[0], self.core.crypto.mac_key)
        return result

    def _guarded_add_block(self, *args: Any, **kwargs: Any):
        if not self.verify_chain():
            raise LedgerIntegrityError("refusing append because existing ledger integrity failed")
        old_len = len(self.core.chain)
        was_archived = {
            i: bool(getattr(block, "archived_pruned", False))
            for i, block in enumerate(self.core.chain)
        }

        result = self._original_add_block(*args, **kwargs)

        for i, block in enumerate(self.core.chain[:old_len]):
            if verify_block_integrity(block, self.core.crypto.mac_key):
                continue
            transitioned = (
                not was_archived.get(i, False)
                and bool(getattr(block, "archived_pruned", False))
            )
            if (
                not transitioned
                or not self._verify_archive_reference(block)
                or not self._verify_validator_signature(block)
            ):
                raise LedgerIntegrityError(
                    f"existing committed block {i} mutated outside an approved archive transition"
                )
            seal_block_integrity(block, self.core.crypto.mac_key)

        for block in self.core.chain[old_len:]:
            if not self._verify_validator_signature(block):
                raise LedgerIntegrityError(
                    f"new block {getattr(block, 'index', '?')} has an invalid validator signature"
                )
            seal_block_integrity(block, self.core.crypto.mac_key)

        if not self.verify_chain():
            raise LedgerIntegrityError("ledger failed validation after append")
        return result

    def metadata(self) -> Dict[str, Any]:
        return {
            "version": LEDGER_SEAL_VERSION,
            "full_metadata_seal": True,
            "genesis_verified": True,
            "validator_signature_verified_for_all_blocks": True,
            "archive_transition_fail_closed": True,
            "sealed_blocks": len(self.core.chain),
        }


def _sha2_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha3_text(value: str) -> str:
    return hashlib.sha3_256(value.encode("utf-8")).hexdigest()


def _go_bool(value: Any) -> str:
    return "true" if bool(value) else "false"


def _go_float(value: Any, digits: int) -> str:
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise LedgerIntegrityError("Go telemetry contains a non-finite value")
    return f"{number:.{digits}f}"


def go_telemetry_string(telemetry: Mapping[str, Any]) -> str:
    t = telemetry
    return ",".join(
        [
            _go_float(t.get("speed", 0.0), 6),
            _go_float(t.get("acceleration", 0.0), 6),
            _go_float(t.get("fuel_level", 0.0), 6),
            _go_float(t.get("battery_voltage", 0.0), 6),
            _go_float(t.get("engine_temp", 0.0), 6),
            _go_float(t.get("gps_lat", 0.0), 8),
            _go_float(t.get("gps_lon", 0.0), 8),
            _go_float(t.get("obstacle_distance", 0.0), 6),
            _go_bool(t.get("emergency_brake_active", False)),
            _go_float(t.get("steering_angle", 0.0), 6),
            _go_float(t.get("brake_pressure", 0.0), 6),
            _go_float(t.get("throttle_position", 0.0), 6),
            _go_float(t.get("rpm", 0.0), 6),
            _go_float(t.get("odometer", 0.0), 6),
            _go_float(t.get("driver_heart_rate_bpm", 0.0), 6),
            _go_float(t.get("driver_drowsiness_score", 0.0), 6),
            _go_bool(t.get("driver_unwell", False)),
            str(t.get("timestamp", "")),
        ]
    )


def verify_go_block(
    block: Mapping[str, Any],
    previous_hash: Optional[str],
    expected_vehicle_id: str,
    position: int,
) -> None:
    try:
        index = int(block.get("index", -1))
    except Exception as exc:
        raise LedgerIntegrityError("Go block index is invalid") from exc
    if index != position:
        raise LedgerIntegrityError(f"Go block index mismatch at position {position}")
    if str(block.get("vehicle_id", "")) != str(expected_vehicle_id):
        raise LedgerIntegrityError(f"Go block {index} vehicle identity mismatch")

    actual_previous = str(block.get("previous_hash", ""))
    expected_previous = "0" if position == 0 else str(previous_hash or "")
    if actual_previous != expected_previous:
        raise LedgerIntegrityError(f"Go block {index} previous-hash linkage failed")

    telemetry = block.get("telemetry")
    if not isinstance(telemetry, Mapping):
        raise LedgerIntegrityError(f"Go block {index} telemetry is not an object")
    telemetry_text = go_telemetry_string(telemetry)
    event_data = str(block.get("event_data", ""))

    tel_sha2 = _sha2_text(telemetry_text)
    tel_sha3 = _sha3_text(telemetry_text)
    event_sha2 = _sha2_text(event_data)
    event_sha3 = _sha3_text(event_data)

    if not hmac.compare_digest(str(block.get("telemetry_hash_sha2", "")), tel_sha2):
        raise LedgerIntegrityError(f"Go block {index} telemetry SHA2 mismatch")
    if not hmac.compare_digest(str(block.get("telemetry_hash_sha3", "")), tel_sha3):
        raise LedgerIntegrityError(f"Go block {index} telemetry SHA3 mismatch")
    if not hmac.compare_digest(str(block.get("event_hash_sha2", "")), event_sha2):
        raise LedgerIntegrityError(f"Go block {index} event SHA2 mismatch")
    if not hmac.compare_digest(str(block.get("event_hash_sha3", "")), event_sha3):
        raise LedgerIntegrityError(f"Go block {index} event SHA3 mismatch")

    raw = (
        f"{index}{block.get('timestamp', '')}{expected_vehicle_id}"
        f"{tel_sha3}{event_sha3}{actual_previous}"
    )
    expected_block_hash = _sha3_text(raw)
    actual_block_hash = str(block.get("block_hash", ""))
    if not hmac.compare_digest(actual_block_hash, expected_block_hash):
        raise LedgerIntegrityError(f"Go block {index} block hash mismatch")

    expected_dual = _sha2_text(actual_block_hash) + ":" + _sha3_text(actual_block_hash)
    if not hmac.compare_digest(str(block.get("dual_hash_combined", "")), expected_dual):
        raise LedgerIntegrityError(f"Go block {index} dual hash mismatch")


class GoLedgerSnapshotVerifier:
    """Validate Go hashes and reject retroactive changes to previously observed full blocks."""

    def __init__(self, vehicle_id: str):
        self.vehicle_id = str(vehicle_id)
        self._generation = ""
        self._fingerprints: Dict[int, str] = {}
        self.last_valid = False

    def reset(self, generation: str = "") -> None:
        self._generation = str(generation)
        self._fingerprints.clear()
        self.last_valid = False

    @staticmethod
    def _fingerprint(block: Mapping[str, Any]) -> str:
        raw = json.dumps(
            _jsonable(dict(block)),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return hashlib.sha3_256(raw.encode("utf-8")).hexdigest()

    def verify_and_track(
        self,
        chain: Iterable[Mapping[str, Any]],
        generation: str,
    ) -> bool:
        blocks = list(chain)
        generation = str(generation)
        if not generation:
            raise LedgerIntegrityError("authenticated Go service instance id is missing")
        if generation != self._generation:
            self.reset(generation)
        if not blocks:
            raise LedgerIntegrityError("Go ledger is empty")
        if len(blocks) < len(self._fingerprints):
            raise LedgerIntegrityError("Go ledger length regressed")

        pending: Dict[int, str] = {}
        previous_hash: Optional[str] = None
        for position, block in enumerate(blocks):
            if not isinstance(block, Mapping):
                raise LedgerIntegrityError(f"Go block {position} is not an object")
            verify_go_block(block, previous_hash, self.vehicle_id, position)
            fingerprint = self._fingerprint(block)
            known = self._fingerprints.get(position)
            if known is not None and not hmac.compare_digest(known, fingerprint):
                raise LedgerIntegrityError(f"Go block {position} changed after commit")
            pending[position] = fingerprint
            previous_hash = str(block.get("block_hash", ""))

        self._fingerprints.update(pending)
        self.last_valid = True
        return True

    def metadata(self) -> Dict[str, Any]:
        return {
            "version": LEDGER_SEAL_VERSION,
            "go_hashes_independently_recomputed": True,
            "retroactive_full_block_mutation_rejected": True,
            "tracked_blocks": len(self._fingerprints),
            "service_generation": self._generation,
            "last_valid": self.last_valid,
        }
