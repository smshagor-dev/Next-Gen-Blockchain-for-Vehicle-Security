# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
SmartCar Network Sync Protocol.

Security-hardening branch behavior:
- fail-closed secret loading
- authenticated handshake
- mandatory MAC after session establishment
- timestamp + nonce replay protection
- session-to-vehicle identity binding
- validator allow-list binding for votes
- reject invalid chains without mutating server state
"""

import hashlib
import hmac
import json
import logging
import secrets
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from env_config import (
    get_env,
    get_int,
    get_required_secret,
    load_project_env_once,
)

try:
    from zkp_privacy import verify_location_ownership_proof, verify_speed_limit_proof
except Exception:
    from zkp_privacy import verify_location_ownership_proof, verify_speed_limit_proof

load_project_env_once()
logger = logging.getLogger("SmartCarNetwork")

MAX_MESSAGE_BYTES = 1_048_576
DEFAULT_REPLAY_WINDOW_SEC = 15
DEFAULT_MAX_CHAIN_BLOCKS = 10_000
GENESIS_PREVIOUS_HASH = "0" * 64


class MessageType:
    HANDSHAKE = "HANDSHAKE"
    HANDSHAKE_ACK = "HANDSHAKE_ACK"
    SYNC_REQUEST = "SYNC_REQUEST"
    SYNC_RESPONSE = "SYNC_RESPONSE"
    BLOCK_UPDATE = "BLOCK_UPDATE"
    VERIFY_REQUEST = "VERIFY_REQUEST"
    VERIFY_RESPONSE = "VERIFY_RESPONSE"
    EMERGENCY = "EMERGENCY"
    PING = "PING"
    PONG = "PONG"
    ERROR = "ERROR"
    AUTH_CHALLENGE = "AUTH_CHALLENGE"
    AUTH_RESPONSE = "AUTH_RESPONSE"
    VOTE_SUBMIT = "VOTE_SUBMIT"
    VOTE_TALLY_REQUEST = "VOTE_TALLY_REQUEST"
    VOTE_TALLY_RESPONSE = "VOTE_TALLY_RESPONSE"


def sha3_256(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()


def sha2_256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def poa_sign_block(block_hash: str, validator_id: str, authority_round: int, validator_key: str) -> str:
    payload = f"{block_hash}|{validator_id}|{authority_round}"
    return hmac.new(validator_key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _nonce() -> str:
    return secrets.token_hex(16)


def _parse_timestamp(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _is_fresh_timestamp(value: str, max_skew_sec: int) -> bool:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return False
    skew = abs((datetime.now(timezone.utc) - parsed).total_seconds())
    return skew <= max(1, int(max_skew_sec))


def _prune_replay_cache(cache: Dict[str, float], now: float) -> None:
    stale = [nonce for nonce, expiry in cache.items() if expiry <= now]
    for nonce in stale:
        cache.pop(nonce, None)


def _claim_nonce(cache: Optional[Dict[str, float]], nonce: str, window_sec: int) -> bool:
    if cache is None:
        return True
    now = time.monotonic()
    _prune_replay_cache(cache, now)
    if nonce in cache:
        return False
    cache[nonce] = now + max(1, int(window_sec))
    return True


def _validate_secret_value(value: str, name: str, min_length: int = 32) -> str:
    secret = str(value or "").strip()
    if len(secret) < min_length:
        raise RuntimeError(f"{name} must contain at least {min_length} characters")
    forbidden = {
        "SmartCarNetworkKey2024",
        "SMARTCAR_SYNC_SHARED_KEY",
        "change-me",
        "changeme",
        "default",
        "password",
        "secret",
    }
    if secret in forbidden:
        raise RuntimeError(f"{name} uses an insecure placeholder/default value")
    return secret


def _load_json_secret_map(env_name: str) -> Dict[str, str]:
    raw = get_env(env_name, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"{env_name} must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{env_name} must be a JSON object")
    result: Dict[str, str] = {}
    for identity, secret in parsed.items():
        identity = str(identity).strip()
        if not identity:
            raise RuntimeError(f"{env_name} contains an empty identity")
        result[identity] = _validate_secret_value(str(secret), f"{env_name}[{identity}]")
    return result


def create_message(msg_type: str, payload: dict, session_key: str = "") -> bytes:
    """Create one newline-delimited protocol message.

    A session MAC is attached whenever ``session_key`` is present.
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")
    msg = {
        "type": str(msg_type),
        "payload": payload,
        "timestamp": _utc_now(),
        "nonce": _nonce(),
    }
    if session_key:
        msg["mac"] = hmac.new(
            session_key.encode(),
            _canonical_json(msg).encode(),
            hashlib.sha256,
        ).hexdigest()
    return (_canonical_json(msg) + "\n").encode()


def verify_message(
    raw: str,
    session_key: str = "",
    *,
    replay_cache: Optional[Dict[str, float]] = None,
    max_skew_sec: int = DEFAULT_REPLAY_WINDOW_SEC,
) -> Optional[dict]:
    """Parse and verify a protocol message.

    Once a session key exists, MAC, timestamp freshness, and nonce uniqueness
    are mandatory. Missing authentication is rejected rather than downgraded.
    """
    try:
        if not isinstance(raw, str) or not raw.strip():
            return None
        if len(raw.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
            logger.warning("Message rejected: payload too large")
            return None

        parsed = json.loads(raw.strip())
        if not isinstance(parsed, dict):
            return None

        msg = dict(parsed)
        if not isinstance(msg.get("type"), str) or not msg.get("type"):
            return None
        if not isinstance(msg.get("payload"), dict):
            return None

        timestamp = str(msg.get("timestamp", ""))
        nonce = str(msg.get("nonce", ""))
        if not timestamp or len(nonce) < 16:
            return None

        if session_key:
            mac_received = msg.pop("mac", None)
            if not isinstance(mac_received, str) or not mac_received:
                logger.warning("Message rejected: session MAC missing")
                return None
            expected_mac = hmac.new(
                session_key.encode(),
                _canonical_json(msg).encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(mac_received, expected_mac):
                logger.warning("Message MAC verification FAILED")
                return None
            if not _is_fresh_timestamp(timestamp, max_skew_sec):
                logger.warning("Message rejected: stale/future timestamp")
                return None
            if not _claim_nonce(replay_cache, nonce, max_skew_sec):
                logger.warning("Message rejected: replayed nonce")
                return None
        return msg
    except Exception as exc:
        logger.error("Message parse error: %s", exc)
        return None


def _handshake_auth_payload(message: dict) -> dict:
    return {
        "type": message.get("type"),
        "payload": message.get("payload"),
        "timestamp": message.get("timestamp"),
        "nonce": message.get("nonce"),
    }


def _handshake_mac(shared_key: str, message: dict) -> str:
    return hmac.new(
        shared_key.encode(),
        _canonical_json(_handshake_auth_payload(message)).encode(),
        hashlib.sha256,
    ).hexdigest()


def _derive_session_key(shared_key: str, vehicle_id: str, nonce: str) -> str:
    material = f"OMNIGUARD_SYNC_SESSION_V1|{vehicle_id}|{nonce}".encode()
    return hmac.new(shared_key.encode(), material, hashlib.sha256).hexdigest()


class SyncServer:
    def __init__(
        self,
        host: str = None,
        port: int = None,
        shared_key: str = None,
        authority_registry: Optional[Dict[str, str]] = None,
        vehicle_key_registry: Optional[Dict[str, str]] = None,
        validator_ids: Optional[List[str]] = None,
    ):
        self.host = host or get_env("SMARTCAR_SYNC_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_SYNC_PORT", 9876)

        if shared_key is None:
            shared_key = get_required_secret("SMARTCAR_SYNC_SHARED_KEY", min_length=32)
        self.shared_key = _validate_secret_value(shared_key, "SMARTCAR_SYNC_SHARED_KEY")

        self.vehicle_key_registry = dict(vehicle_key_registry or _load_json_secret_map(
            "SMARTCAR_SYNC_VEHICLE_KEYS_JSON"
        ))
        self.authority_registry = dict(authority_registry or _load_json_secret_map(
            "SMARTCAR_POA_AUTHORITY_REGISTRY_JSON"
        ))
        self.authority_order = sorted(self.authority_registry.keys())

        configured_validators = validator_ids
        if configured_validators is None:
            raw_validators = get_env("SMARTCAR_SYNC_VALIDATOR_IDS", "").strip()
            configured_validators = [
                item.strip() for item in raw_validators.split(",") if item.strip()
            ]
        self.validator_ids = set(configured_validators or self.authority_order)

        self.replay_window_sec = max(
            3, get_int("SMARTCAR_SYNC_REPLAY_WINDOW_SEC", DEFAULT_REPLAY_WINDOW_SEC)
        )
        self.max_chain_blocks = max(
            1, get_int("SMARTCAR_SYNC_MAX_CHAIN_BLOCKS", DEFAULT_MAX_CHAIN_BLOCKS)
        )

        self.server_chain: List[Dict] = []
        self.clients: Dict[str, dict] = {}
        self._running = False
        self._callbacks: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()
        self._handshake_replay_cache: Dict[str, float] = {}
        self.vote_registry: Dict[str, Dict[str, Dict]] = {}

    def on_event(self, event: str, callback: Callable):
        self._callbacks.setdefault(event, []).append(callback)

    def _emit(self, event: str, data):
        for cb in self._callbacks.get(event, []):
            try:
                cb(data)
            except Exception as exc:
                logger.error("Event callback error (%s): %s", event, exc)

    def _vehicle_secret(self, vehicle_id: str) -> str:
        if self.vehicle_key_registry:
            secret = self.vehicle_key_registry.get(vehicle_id, "")
            if not secret:
                raise RuntimeError("UNREGISTERED_VEHICLE")
            return secret
        return self.shared_key

    def start(self):
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.host, self.port))
            self._sock.listen(10)
            self._sock.settimeout(1.0)
        except OSError:
            self._running = False
            try:
                self._sock.close()
            except Exception:
                pass
            raise
        threading.Thread(target=self._accept_loop, daemon=True).start()
        logger.info("SyncServer listening on %s:%s", self.host, self.port)

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except Exception:
            pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.exception("Accept socket error")
                break

    def _handle_client(self, conn: socket.socket, addr):
        client_id = f"{addr[0]}:{addr[1]}"
        logger.info("Client connected: %s", client_id)
        conn.settimeout(2.0)
        try:
            buf = ""
            while self._running:
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                    break
                if not data:
                    break
                buf += data.decode(errors="replace")
                if len(buf.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
                    logger.warning("Client %s exceeded message buffer limit", client_id)
                    break

                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if not line.strip():
                        continue
                    state = self.clients.get(client_id, {})
                    session_key = state.get("session_key", "")
                    replay_cache = state.get("replay_cache") if session_key else None
                    msg = verify_message(
                        line,
                        session_key,
                        replay_cache=replay_cache,
                        max_skew_sec=self.replay_window_sec,
                    )
                    if not msg:
                        if session_key:
                            self._safe_send(
                                conn,
                                create_message(
                                    MessageType.ERROR,
                                    {"reason": "AUTHENTICATION_FAILED"},
                                    session_key,
                                ),
                                client_id,
                            )
                        continue

                    if not session_key and msg.get("type") != MessageType.HANDSHAKE:
                        logger.warning("Unauthenticated message rejected from %s", client_id)
                        continue

                    response = self._process_message(msg, client_id, session_key)
                    if response and not self._safe_send(conn, response, client_id):
                        break
        finally:
            with self._lock:
                self.clients.pop(client_id, None)
            try:
                conn.close()
            except Exception:
                pass
            logger.info("Client disconnected: %s", client_id)

    def _safe_send(self, conn: socket.socket, payload: bytes, client_id: str) -> bool:
        try:
            conn.sendall(payload)
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            logger.info("Client %s disconnected during send", client_id)
            return False

    def _error(self, reason: str, session_key: str) -> Optional[bytes]:
        if not session_key:
            return None
        return create_message(MessageType.ERROR, {"reason": reason}, session_key)

    def _verify_handshake(self, msg: dict) -> Optional[str]:
        payload = msg.get("payload", {})
        vehicle_id = str(payload.get("vehicle_id", "")).strip()
        client_version = str(payload.get("client_version", "")).strip()
        supplied = str(msg.get("handshake_mac", ""))
        if not vehicle_id or not client_version or not supplied:
            return None
        if not _is_fresh_timestamp(str(msg.get("timestamp", "")), self.replay_window_sec):
            return None
        nonce = str(msg.get("nonce", ""))
        if len(nonce) < 16:
            return None

        try:
            vehicle_secret = self._vehicle_secret(vehicle_id)
        except RuntimeError:
            logger.warning("Handshake rejected for unregistered vehicle %s", vehicle_id)
            return None

        expected = _handshake_mac(vehicle_secret, msg)
        if not hmac.compare_digest(supplied, expected):
            logger.warning("Handshake authentication failed for %s", vehicle_id)
            return None
        if not _claim_nonce(self._handshake_replay_cache, nonce, self.replay_window_sec):
            logger.warning("Handshake replay rejected for %s", vehicle_id)
            return None
        return vehicle_id

    def _bound_vehicle(self, client_id: str) -> str:
        return str(self.clients.get(client_id, {}).get("vehicle_id", ""))

    def _payload_matches_session(self, client_id: str, payload: dict) -> bool:
        bound = self._bound_vehicle(client_id)
        claimed = str(payload.get("vehicle_id", "")).strip()
        return bool(bound) and (not claimed or hmac.compare_digest(bound, claimed))

    def _process_message(self, msg: dict, client_id: str, session_key: str) -> Optional[bytes]:
        mtype = msg.get("type")
        payload = msg.get("payload", {})

        if mtype == MessageType.HANDSHAKE:
            if session_key:
                return self._error("SESSION_ALREADY_ESTABLISHED", session_key)
            vehicle_id = self._verify_handshake(msg)
            if not vehicle_id:
                return None
            vehicle_secret = self._vehicle_secret(vehicle_id)
            session_key = _derive_session_key(
                vehicle_secret,
                vehicle_id,
                str(msg.get("nonce", "")),
            )
            with self._lock:
                self.clients[client_id] = {
                    "vehicle_id": vehicle_id,
                    "session_key": session_key,
                    "connected_at": _utc_now(),
                    "replay_cache": {},
                }
            self._emit("client_connected", {"vehicle_id": vehicle_id, "client_id": client_id})
            return create_message(
                MessageType.HANDSHAKE_ACK,
                {
                    "server": "OmniGuard-SyncNode-v2",
                    "vehicle_id": vehicle_id,
                    "status": "CONNECTED",
                },
                session_key,
            )

        if not session_key or not self._bound_vehicle(client_id):
            return None

        if mtype in {
            MessageType.SYNC_REQUEST,
            MessageType.BLOCK_UPDATE,
            MessageType.VOTE_SUBMIT,
        } and not self._payload_matches_session(client_id, payload):
            return self._error("VEHICLE_IDENTITY_MISMATCH", session_key)

        bound_vehicle = self._bound_vehicle(client_id)

        if mtype == MessageType.SYNC_REQUEST:
            chain = payload.get("chain", [])
            valid = self._verify_chain(chain)
            if valid:
                with self._lock:
                    self.server_chain = [dict(block) for block in chain]
            self._emit(
                "sync_received",
                {"vehicle_id": bound_vehicle, "blocks": len(chain) if isinstance(chain, list) else 0, "valid": valid},
            )
            return create_message(
                MessageType.SYNC_RESPONSE,
                {
                    "accepted": valid,
                    "block_count": len(chain) if isinstance(chain, list) else 0,
                    "latest_hash": chain[-1].get("block_hash", "") if valid and chain else "",
                    "server_chain_length": len(self.server_chain),
                    "integrity": "VALID" if valid else "COMPROMISED",
                },
                session_key,
            )

        if mtype == MessageType.EMERGENCY:
            event = dict(payload)
            event["vehicle_id"] = bound_vehicle
            self._emit("emergency", event)
            logger.critical("EMERGENCY from %s: %s", bound_vehicle, event)
            return create_message(
                MessageType.VERIFY_RESPONSE,
                {
                    "emergency_acknowledged": True,
                    "vehicle_id": bound_vehicle,
                    "action": "EMERGENCY_SERVICES_NOTIFIED",
                },
                session_key,
            )

        if mtype == MessageType.PING:
            return create_message(MessageType.PONG, {"latency_check": True}, session_key)

        if mtype == MessageType.BLOCK_UPDATE:
            block = payload.get("block", {})
            candidate = list(self.server_chain)
            if not candidate:
                candidate = [block]
            else:
                candidate.append(block)
            valid = self._verify_chain(candidate)
            if not valid:
                return self._error("INVALID_BLOCK_UPDATE", session_key)
            with self._lock:
                self.server_chain = [dict(item) for item in candidate]
            self._emit("block_received", {"vehicle_id": bound_vehicle, "block": block})
            return create_message(
                MessageType.SYNC_RESPONSE,
                {
                    "block_received": True,
                    "block_index": block.get("index", -1),
                    "server_chain_length": len(self.server_chain),
                },
                session_key,
            )

        if mtype == MessageType.VOTE_SUBMIT:
            proposal_id = str(payload.get("proposal_id", "")).strip()
            claimed_voter = str(payload.get("voter_id", "")).strip()
            if not proposal_id:
                return self._error("INVALID_PROPOSAL_ID", session_key)
            if claimed_voter and not hmac.compare_digest(claimed_voter, bound_vehicle):
                return self._error("VOTER_IDENTITY_MISMATCH", session_key)
            if not self.validator_ids or bound_vehicle not in self.validator_ids:
                return self._error("VALIDATOR_NOT_AUTHORIZED", session_key)

            vote = bool(payload.get("vote", False))
            reason = str(payload.get("reason", ""))
            with self._lock:
                votes = self.vote_registry.setdefault(proposal_id, {})
                votes[bound_vehicle] = {
                    "vote": vote,
                    "reason": reason,
                    "timestamp": _utc_now(),
                }
                yes_votes = sum(1 for value in votes.values() if value.get("vote"))
                no_votes = len(votes) - yes_votes
            return create_message(
                MessageType.VOTE_TALLY_RESPONSE,
                {
                    "proposal_id": proposal_id,
                    "acknowledged": True,
                    "voter_id": bound_vehicle,
                    "yes_votes": yes_votes,
                    "no_votes": no_votes,
                    "total_votes": len(votes),
                    "majority_accept": yes_votes > (len(votes) / 2.0),
                },
                session_key,
            )

        if mtype == MessageType.VOTE_TALLY_REQUEST:
            proposal_id = str(payload.get("proposal_id", "")).strip()
            with self._lock:
                votes = dict(self.vote_registry.get(proposal_id, {}))
            yes_votes = sum(1 for value in votes.values() if value.get("vote"))
            no_votes = len(votes) - yes_votes
            return create_message(
                MessageType.VOTE_TALLY_RESPONSE,
                {
                    "proposal_id": proposal_id,
                    "yes_votes": yes_votes,
                    "no_votes": no_votes,
                    "total_votes": len(votes),
                    "votes": votes,
                    "majority_accept": yes_votes > (len(votes) / 2.0),
                },
                session_key,
            )

        return self._error("UNSUPPORTED_MESSAGE_TYPE", session_key)

    def _verify_chain(self, chain: List[Dict]) -> bool:
        """Verify genesis, sequential linkage, event hash, block hash, PoA, and optional ZKP."""
        if not isinstance(chain, list) or not chain or len(chain) > self.max_chain_blocks:
            return False

        for i, curr in enumerate(chain):
            if not isinstance(curr, dict):
                return False
            try:
                if int(curr.get("index", -1)) != i:
                    return False
                timestamp = str(curr["timestamp"])
                vehicle_id = str(curr["vehicle_id"])
                telemetry_hash_sha3 = str(curr["telemetry_hash_sha3"])
                event_hash_sha3 = str(curr["event_hash_sha3"])
                previous_hash = str(curr["previous_hash"])
                block_hash = str(curr["block_hash"])
            except Exception:
                return False

            if not timestamp or not vehicle_id or len(block_hash) != 64:
                return False

            if i == 0:
                if previous_hash != GENESIS_PREVIOUS_HASH:
                    return False
            else:
                prev = chain[i - 1]
                if previous_hash != str(prev.get("block_hash", "")):
                    return False

            if "event_data" in curr:
                if sha3_256(str(curr.get("event_data", ""))) != event_hash_sha3:
                    return False

            raw = (
                f"{i}{timestamp}{vehicle_id}"
                f"{telemetry_hash_sha3}{event_hash_sha3}{previous_hash}"
            )
            if not hmac.compare_digest(sha3_256(raw), block_hash):
                return False

            if curr.get("consensus") == "POA":
                validator_id = str(curr.get("validator_id", ""))
                authority_round = curr.get("authority_round")
                poa_sig = str(curr.get("poa_signature", ""))
                if authority_round != i or not self.authority_order:
                    return False
                expected_validator = self.authority_order[i % len(self.authority_order)]
                if validator_id != expected_validator:
                    return False
                validator_key = self.authority_registry.get(validator_id, "")
                if not validator_key:
                    return False
                expected_sig = poa_sign_block(block_hash, validator_id, i, validator_key)
                if not hmac.compare_digest(poa_sig, expected_sig):
                    return False

            if curr.get("privacy_preserving"):
                proof_ctx = f"{vehicle_id}|{i}|{timestamp}|{block_hash}"
                zkp = curr.get("zkp_proofs", {})
                if not isinstance(zkp, dict):
                    return False
                if not verify_speed_limit_proof(zkp.get("speed_limit", {}), proof_ctx):
                    return False
                if not verify_location_ownership_proof(
                    zkp.get("location_ownership", {}),
                    proof_ctx,
                ):
                    return False
        return True


class SyncClient:
    def __init__(
        self,
        host: str = None,
        port: int = None,
        vehicle_id: str = None,
        shared_key: str = None,
    ):
        self.host = host or get_env("SMARTCAR_SYNC_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_SYNC_PORT", 9876)
        self.vehicle_id = vehicle_id or get_env("SMARTCAR_VEHICLE_ID", "").strip()
        if not self.vehicle_id:
            raise RuntimeError("SMARTCAR_VEHICLE_ID is required")

        if shared_key is None:
            shared_key = get_required_secret("SMARTCAR_SYNC_SHARED_KEY", min_length=32)
        self.shared_key = _validate_secret_value(shared_key, "SMARTCAR_SYNC_SHARED_KEY")

        self.replay_window_sec = max(
            3, get_int("SMARTCAR_SYNC_REPLAY_WINDOW_SEC", DEFAULT_REPLAY_WINDOW_SEC)
        )
        self.session_key = ""
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._lock = threading.Lock()
        self._replay_cache: Dict[str, float] = {}

    def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(5.0)
            self._sock.connect((self.host, self.port))

            handshake = {
                "type": MessageType.HANDSHAKE,
                "payload": {
                    "vehicle_id": self.vehicle_id,
                    "client_version": "2.0",
                },
                "timestamp": _utc_now(),
                "nonce": _nonce(),
            }
            handshake["handshake_mac"] = _handshake_mac(self.shared_key, handshake)
            self._sock.sendall((_canonical_json(handshake) + "\n").encode())

            resp_raw = self._receive_line()
            if not resp_raw:
                return False

            self.session_key = _derive_session_key(
                self.shared_key,
                self.vehicle_id,
                handshake["nonce"],
            )
            resp = verify_message(
                resp_raw,
                self.session_key,
                replay_cache=self._replay_cache,
                max_skew_sec=self.replay_window_sec,
            )
            if (
                resp
                and resp.get("type") == MessageType.HANDSHAKE_ACK
                and str(resp.get("payload", {}).get("vehicle_id", "")) == self.vehicle_id
            ):
                self._connected = True
                logger.info("Connected to sync server: %s:%s", self.host, self.port)
                return True

            self.session_key = ""
            return False
        except Exception as exc:
            logger.error("Connection failed: %s", exc)
            self.disconnect()
            return False

    def _receive_line(self) -> Optional[str]:
        if not self._sock:
            return None
        buf = ""
        try:
            while "\n" not in buf:
                chunk = self._sock.recv(4096)
                if not chunk:
                    return None
                buf += chunk.decode(errors="replace")
                if len(buf.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
                    return None
            return buf.split("\n", 1)[0]
        except (socket.timeout, OSError, ConnectionResetError, ConnectionAbortedError):
            return None

    def _send_recv(self, msg: bytes) -> Optional[dict]:
        if not self._sock or not self.session_key:
            self._connected = False
            return None
        with self._lock:
            try:
                self._sock.sendall(msg)
                raw = self._receive_line()
                if raw:
                    return verify_message(
                        raw,
                        self.session_key,
                        replay_cache=self._replay_cache,
                        max_skew_sec=self.replay_window_sec,
                    )
                return None
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                self._connected = False
                return None

    def sync_chain(self, chain: list) -> Optional[Dict]:
        if not self._connected:
            return None
        return self._send_recv(
            create_message(
                MessageType.SYNC_REQUEST,
                {
                    "vehicle_id": self.vehicle_id,
                    "chain": chain,
                    "block_count": len(chain),
                },
                self.session_key,
            )
        )

    def send_block_update(self, block: dict) -> Optional[Dict]:
        if not self._connected:
            return None
        return self._send_recv(
            create_message(
                MessageType.BLOCK_UPDATE,
                {"vehicle_id": self.vehicle_id, "block": block},
                self.session_key,
            )
        )

    def send_emergency(self, data: dict) -> Optional[Dict]:
        if not self._connected:
            return None
        payload = dict(data)
        payload["vehicle_id"] = self.vehicle_id
        return self._send_recv(
            create_message(MessageType.EMERGENCY, payload, self.session_key)
        )

    def ping(self) -> bool:
        if not self._connected:
            return False
        resp = self._send_recv(create_message(MessageType.PING, {}, self.session_key))
        return resp is not None and resp.get("type") == MessageType.PONG

    def disconnect(self):
        self._connected = False
        self.session_key = ""
        self._replay_cache.clear()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def submit_vote(
        self,
        proposal_id: str,
        voter_id: str,
        vote: bool,
        reason: str = "",
    ) -> Optional[Dict]:
        if not self._connected:
            return None
        if voter_id and voter_id != self.vehicle_id:
            raise ValueError("voter_id must match the authenticated vehicle identity")
        return self._send_recv(
            create_message(
                MessageType.VOTE_SUBMIT,
                {
                    "proposal_id": proposal_id,
                    "voter_id": self.vehicle_id,
                    "vehicle_id": self.vehicle_id,
                    "vote": bool(vote),
                    "reason": reason,
                },
                self.session_key,
            )
        )

    def request_vote_tally(self, proposal_id: str) -> Optional[Dict]:
        if not self._connected:
            return None
        return self._send_recv(
            create_message(
                MessageType.VOTE_TALLY_REQUEST,
                {"proposal_id": proposal_id},
                self.session_key,
            )
        )


if __name__ == "__main__":
    print(
        "OmniGuard sync protocol security hardening enabled. "
        "Configure SMARTCAR_SYNC_SHARED_KEY before running the network demo."
    )
