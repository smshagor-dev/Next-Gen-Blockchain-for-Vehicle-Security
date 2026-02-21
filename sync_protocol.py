# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
SmartCar Network Sync Protocol
- Blockchain sync between car and server
- Encrypted communication
- Hash verification on sync
"""

import json
import socket
import threading
import hashlib
import hmac
import time
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Callable
import sys
import os

logger = logging.getLogger('SmartCarNetwork')

try:
    from env_config import load_project_env_once, get_env, get_int
except Exception:
    from env_config import load_project_env_once, get_env, get_int

load_project_env_once()

DEFAULT_POA_AUTHORITY_REGISTRY = {
    "authority_node_1": "SmartCarPoAKey_2024_Node1"
}

try:
    from zkp_privacy import verify_speed_limit_proof, verify_location_ownership_proof
except Exception:
    from zkp_privacy import verify_speed_limit_proof, verify_location_ownership_proof

# ============================================================
# Sync Protocol Messages
# ============================================================

class MessageType:
    HANDSHAKE     = "HANDSHAKE"
    HANDSHAKE_ACK = "HANDSHAKE_ACK"
    SYNC_REQUEST  = "SYNC_REQUEST"
    SYNC_RESPONSE = "SYNC_RESPONSE"
    BLOCK_UPDATE  = "BLOCK_UPDATE"
    VERIFY_REQUEST = "VERIFY_REQUEST"
    VERIFY_RESPONSE = "VERIFY_RESPONSE"
    EMERGENCY     = "EMERGENCY"
    PING          = "PING"
    PONG          = "PONG"
    ERROR         = "ERROR"
    AUTH_CHALLENGE = "AUTH_CHALLENGE"
    AUTH_RESPONSE  = "AUTH_RESPONSE"
    VOTE_SUBMIT = "VOTE_SUBMIT"
    VOTE_TALLY_REQUEST = "VOTE_TALLY_REQUEST"
    VOTE_TALLY_RESPONSE = "VOTE_TALLY_RESPONSE"

def sha3_256(data: str) -> str:
    """Return SHA3-256 hex digest."""
    return hashlib.sha3_256(data.encode()).hexdigest()

def sha2_256(data: str) -> str:
    """Return SHA2-256 hex digest."""
    return hashlib.sha256(data.encode()).hexdigest()


def poa_sign_block(block_hash: str, validator_id: str, authority_round: int, validator_key: str) -> str:
    """Create PoA signature over block metadata."""
    payload = f"{block_hash}|{validator_id}|{authority_round}"
    return hmac.new(validator_key.encode(), payload.encode(), hashlib.sha256).hexdigest()

def create_message(msg_type: str, payload: dict, session_key: str = "") -> bytes:
    """Create authenticated network message"""
    msg = {
        'type': msg_type,
        'payload': payload,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'nonce': sha3_256(str(time.time()) + msg_type)[:16]
    }
    msg_str = json.dumps(msg, sort_keys=True)
    if session_key:
        mac = hmac.new(session_key.encode(), msg_str.encode(), hashlib.sha256).hexdigest()
        msg['mac'] = mac
        msg_str = json.dumps(msg, sort_keys=True)
    return (msg_str + '\n').encode()

def verify_message(raw: str, session_key: str = "") -> Optional[dict]:
    """Verify and parse network message"""
    try:
        msg = json.loads(raw.strip())
        if session_key and 'mac' in msg:
            mac_received = msg.pop('mac')
            msg_str = json.dumps(msg, sort_keys=True)
            expected_mac = hmac.new(session_key.encode(), msg_str.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac_received, expected_mac):
                logger.warning("Message MAC verification FAILED")
                return None
        return msg
    except Exception as e:
        logger.error(f"Message parse error: {e}")
        return None


# ============================================================
# Blockchain Sync Server (Vehicle Infrastructure Node)
# ============================================================

class SyncServer:
    def __init__(self, host: str = None, port: int = None,
                 shared_key: str = None,
                 authority_registry: Optional[Dict[str, str]] = None):
        """Initialize sync server state and consensus registry."""
        self.host = host or get_env("SMARTCAR_SYNC_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_SYNC_PORT", 9876)
        self.shared_key = shared_key or get_env("SMARTCAR_SYNC_SHARED_KEY", "SmartCarNetworkKey2024")
        self.authority_registry = dict(authority_registry or DEFAULT_POA_AUTHORITY_REGISTRY)
        self.authority_order = sorted(self.authority_registry.keys())
        self.server_chain: List[Dict] = []
        self.clients: Dict[str, dict] = {}
        self._running = False
        self._callbacks: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()
        self.vote_registry: Dict[str, Dict[str, Dict]] = {}

    def on_event(self, event: str, callback: Callable):
        """Register callback for server events."""
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)

    def _emit(self, event: str, data):
        """Emit event to registered callbacks."""
        for cb in self._callbacks.get(event, []):
            try:
                cb(data)
            except Exception as e:
                logger.error(f"Event callback error ({event}): {e}")

    def start(self):
        """Start TCP sync server and accept loop."""
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.host, self.port))
            self._sock.listen(10)
            self._sock.settimeout(1.0)
        except OSError as e:
            self._running = False
            logger.error(f"SyncServer bind/listen failed on {self.host}:{self.port} - {e}")
            try:
                self._sock.close()
            except Exception as close_err:
                logger.debug(f"SyncServer socket close after bind failure: {close_err}")
            raise
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        logger.info(f"SyncServer listening on {self.host}:{self.port}")

    def stop(self):
        """Stop server and close all active sockets."""
        self._running = False
        try:
            self._sock.close()
        except Exception as e:
            logger.debug(f"SyncServer socket close error: {e}")

    def _accept_loop(self):
        """Accept clients and spawn per-client handlers."""
        while self._running:
            try:
                conn, addr = self._sock.accept()
                t = threading.Thread(target=self._handle_client,
                                   args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.exception("Accept socket error")
                break
            except Exception as e:
                if self._running:
                    logger.error(f"Accept error: {e}")

    def _handle_client(self, conn: socket.socket, addr):
        """Handle one client socket lifecycle."""
        client_id = f"{addr[0]}:{addr[1]}"
        logger.info(f"Client connected: {client_id}")
        conn.settimeout(2.0)
        try:
            buf = ""
            while self._running:
                try:
                    data = conn.recv(4096).decode(errors='replace')
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                    break
                except OSError as e:
                    logger.warning(f"Client {client_id} socket recv error: {e}")
                    break
                if not data:
                    break
                buf += data
                while '\n' in buf:
                    line, buf = buf.split('\n', 1)
                    if not line.strip():
                        continue
                    session_key = self.clients.get(client_id, {}).get('session_key', '')
                    msg = verify_message(line, session_key)
                    if not msg:
                        self._safe_send(conn, create_message(
                            MessageType.ERROR, {'reason': 'INVALID_MAC'}, session_key
                        ), client_id)
                        continue
                    response = self._process_message(msg, client_id, session_key)
                    if response:
                        if not self._safe_send(conn, response, client_id):
                            break
        except Exception as e:
            logger.error(f"Client {client_id} error: {e}")
        finally:
            with self._lock:
                self.clients.pop(client_id, None)
            try:
                conn.close()
            except Exception as e:
                logger.debug(f"Client {client_id} close error: {e}")
            logger.info(f"Client disconnected: {client_id}")

    def _safe_send(self, conn: socket.socket, payload: bytes, client_id: str) -> bool:
        """Send data to client with guarded socket exceptions."""
        try:
            conn.sendall(payload)
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            logger.info(f"Client {client_id} disconnected during send")
            return False
        except OSError as e:
            logger.warning(f"Client {client_id} socket send error: {e}")
            return False

    def _process_message(self, msg: dict, client_id: str, session_key: str) -> Optional[bytes]:
        """Process one validated sync message."""
        mtype = msg.get('type')
        payload = msg.get('payload', {})

        if mtype == MessageType.HANDSHAKE:
            vehicle_id = payload.get('vehicle_id', 'unknown')
            session_key = sha3_256(self.shared_key + vehicle_id + msg.get('nonce',''))[:32]
            with self._lock:
                self.clients[client_id] = {
                    'vehicle_id': vehicle_id,
                    'session_key': session_key,
                    'connected_at': datetime.now(timezone.utc).isoformat()
                }
            self._emit('client_connected', {'vehicle_id': vehicle_id, 'client_id': client_id})
            return create_message(MessageType.HANDSHAKE_ACK, {
                'server': 'SmartCar-SyncNode-v1',
                'vehicle_id': vehicle_id,
                'status': 'CONNECTED'
            }, session_key)

        elif mtype == MessageType.SYNC_REQUEST:
            chain = payload.get('chain', [])
            vehicle_id = payload.get('vehicle_id', '')
            # Verify chain integrity
            valid = self._verify_chain(chain)
            # Store/merge chain
            with self._lock:
                self.server_chain = chain
            self._emit('sync_received', {'vehicle_id': vehicle_id, 'blocks': len(chain), 'valid': valid})
            return create_message(MessageType.SYNC_RESPONSE, {
                'accepted': valid,
                'block_count': len(chain),
                'latest_hash': chain[-1]['block_hash'] if chain else '',
                'server_chain_length': len(self.server_chain),
                'integrity': 'VALID' if valid else 'COMPROMISED'
            }, session_key)

        elif mtype == MessageType.EMERGENCY:
            data = payload
            self._emit('emergency', data)
            logger.critical(f"EMERGENCY from {client_id}: {data}")
            return create_message(MessageType.VERIFY_RESPONSE, {
                'emergency_acknowledged': True,
                'action': 'EMERGENCY_SERVICES_NOTIFIED'
            }, session_key)

        elif mtype == MessageType.PING:
            return create_message(MessageType.PONG, {'latency_check': True}, session_key)

        elif mtype == MessageType.BLOCK_UPDATE:
            block = payload.get('block', {})
            vehicle_id = payload.get('vehicle_id', '')
            self._emit('block_received', {'vehicle_id': vehicle_id, 'block': block})
            return create_message(MessageType.SYNC_RESPONSE, {
                'block_received': True,
                'block_index': block.get('index', -1)
            }, session_key)

        elif mtype == MessageType.VOTE_SUBMIT:
            proposal_id = payload.get('proposal_id', '')
            voter_id = payload.get('voter_id', '')
            vote = bool(payload.get('vote', False))
            reason = payload.get('reason', '')
            with self._lock:
                if proposal_id not in self.vote_registry:
                    self.vote_registry[proposal_id] = {}
                self.vote_registry[proposal_id][voter_id] = {
                    'vote': vote,
                    'reason': reason,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                votes = self.vote_registry[proposal_id]
                yes_votes = sum(1 for v in votes.values() if v.get('vote'))
                no_votes = len(votes) - yes_votes
            return create_message(MessageType.VOTE_TALLY_RESPONSE, {
                'proposal_id': proposal_id,
                'acknowledged': True,
                'voter_id': voter_id,
                'yes_votes': yes_votes,
                'no_votes': no_votes,
                'total_votes': len(votes),
                'majority_accept': yes_votes > (len(votes) / 2.0),
            }, session_key)

        elif mtype == MessageType.VOTE_TALLY_REQUEST:
            proposal_id = payload.get('proposal_id', '')
            with self._lock:
                votes = dict(self.vote_registry.get(proposal_id, {}))
            yes_votes = sum(1 for v in votes.values() if v.get('vote'))
            no_votes = len(votes) - yes_votes
            return create_message(MessageType.VOTE_TALLY_RESPONSE, {
                'proposal_id': proposal_id,
                'yes_votes': yes_votes,
                'no_votes': no_votes,
                'total_votes': len(votes),
                'votes': votes,
                'majority_accept': yes_votes > (len(votes) / 2.0),
            }, session_key)

        return None

    def _verify_chain(self, chain: List[Dict]) -> bool:
        """Verify block linkage, hashes, PoA, and optional ZKP proofs."""
        for i in range(1, len(chain)):
            curr = chain[i]
            prev = chain[i-1]
            # Verify linkage
            if curr.get('previous_hash') != prev.get('block_hash'):
                return False
            # Verify block hash
            raw = (f"{curr['index']}{curr['timestamp']}{curr['vehicle_id']}"
                   f"{curr['telemetry_hash_sha3']}{curr['event_hash_sha3']}"
                   f"{curr['previous_hash']}")
            expected = sha3_256(raw)
            if expected != curr.get('block_hash'):
                return False
            if curr.get('consensus') == 'POA':
                validator_id = curr.get('validator_id', '')
                authority_round = curr.get('authority_round')
                poa_sig = curr.get('poa_signature', '')
                if authority_round != curr.get('index'):
                    return False
                if not self.authority_order:
                    return False
                expected_validator = self.authority_order[curr.get('index') % len(self.authority_order)]
                if validator_id != expected_validator:
                    return False
                validator_key = self.authority_registry.get(validator_id, '')
                if not validator_key:
                    return False
                expected_sig = poa_sign_block(
                    curr.get('block_hash', ''),
                    validator_id,
                    authority_round,
                    validator_key
                )
                if not hmac.compare_digest(poa_sig, expected_sig):
                    return False
            if curr.get('privacy_preserving'):
                proof_ctx = (
                    f"{curr.get('vehicle_id')}|{curr.get('index')}|"
                    f"{curr.get('timestamp')}|{curr.get('block_hash')}"
                )
                zkp = curr.get('zkp_proofs', {})
                if not verify_speed_limit_proof(zkp.get('speed_limit', {}), proof_ctx):
                    return False
                if not verify_location_ownership_proof(zkp.get('location_ownership', {}), proof_ctx):
                    return False
        return True


# ============================================================
# Sync Client (On-Vehicle Node)
# ============================================================

class SyncClient:
    def __init__(self, host: str = None, port: int = None,
                 vehicle_id: str = None,
                 shared_key: str = None):
        """Initialize vehicle-side sync client."""
        self.host = host or get_env("SMARTCAR_SYNC_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_SYNC_PORT", 9876)
        self.vehicle_id = vehicle_id or get_env("SMARTCAR_VEHICLE_ID", "SMARTCAR_VIN_2024_XYZ789")
        self.shared_key = shared_key or get_env("SMARTCAR_SYNC_SHARED_KEY", "SmartCarNetworkKey2024")
        self.session_key = ""
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._lock = threading.Lock()

    def connect(self) -> bool:
        """Connect and authenticate against sync server."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(5.0)
            self._sock.connect((self.host, self.port))
            # Handshake
            nonce = sha3_256(str(time.time()))[:16]
            handshake = {
                'type': MessageType.HANDSHAKE,
                'payload': {
                    'vehicle_id': self.vehicle_id,
                    'client_version': '1.0',
                },
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'nonce': nonce
            }
            self._sock.sendall((json.dumps(handshake, sort_keys=True) + '\n').encode())
            resp_raw = self._receive_line()
            if resp_raw:
                self.session_key = sha3_256(self.shared_key + self.vehicle_id + nonce)[:32]
                resp = verify_message(resp_raw, self.session_key)
                if resp and resp.get('type') == MessageType.HANDSHAKE_ACK:
                    self._connected = True
                    logger.info(f"Connected to sync server: {self.host}:{self.port}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.disconnect()
            return False

    def _receive_line(self) -> Optional[str]:
        """Receive one newline-terminated protocol line."""
        if not self._sock:
            return None
        buf = ""
        try:
            while '\n' not in buf:
                try:
                    chunk = self._sock.recv(4096).decode(errors='replace')
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                    return None
                if not chunk:
                    return None
                buf += chunk
            return buf.split('\n')[0]
        except OSError as e:
            logger.warning(f"Receive line socket error: {e}")
            return None

    def _send_recv(self, msg: bytes) -> Optional[dict]:
        """Send one request and receive one response."""
        if not self._sock:
            self._connected = False
            return None
        with self._lock:
            try:
                self._sock.sendall(msg)
                raw = self._receive_line()
                if raw:
                    return verify_message(raw, self.session_key)
                return None
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
                logger.error(f"Peer disconnected during send/recv: {e}")
                self._connected = False
                return None
            except Exception as e:
                logger.error(f"Send/recv error: {e}")
                self._connected = False
                return None

    def sync_chain(self, chain: list) -> Optional[Dict]:
        """Submit local chain snapshot for server verification."""
        if not self._connected:
            return None
        return self._send_recv(create_message(MessageType.SYNC_REQUEST, {
            'vehicle_id': self.vehicle_id,
            'chain': chain,
            'block_count': len(chain),
        }, self.session_key))

    def send_block_update(self, block: dict) -> Optional[Dict]:
        """Send latest block update to sync server."""
        if not self._connected:
            return None
        return self._send_recv(create_message(MessageType.BLOCK_UPDATE, {
            'vehicle_id': self.vehicle_id,
            'block': block,
        }, self.session_key))

    def send_emergency(self, data: dict) -> Optional[Dict]:
        """Send emergency event to sync server."""
        if not self._connected:
            return None
        return self._send_recv(create_message(MessageType.EMERGENCY, data, self.session_key))

    def ping(self) -> bool:
        """Check server liveness."""
        if not self._connected:
            return False
        resp = self._send_recv(create_message(MessageType.PING, {}, self.session_key))
        return resp is not None and resp.get('type') == MessageType.PONG

    def disconnect(self):
        """Disconnect from server and close socket."""
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except Exception as e:
                logger.debug(f"SyncClient socket close error: {e}")
            self._sock = None

    def submit_vote(self, proposal_id: str, voter_id: str, vote: bool, reason: str = "") -> Optional[Dict]:
        """Submit majority-vote decision for a proposal."""
        if not self._connected:
            return None
        return self._send_recv(create_message(MessageType.VOTE_SUBMIT, {
            'proposal_id': proposal_id,
            'voter_id': voter_id,
            'vote': bool(vote),
            'reason': reason,
        }, self.session_key))

    def request_vote_tally(self, proposal_id: str) -> Optional[Dict]:
        """Request current majority tally for a proposal."""
        if not self._connected:
            return None
        return self._send_recv(create_message(MessageType.VOTE_TALLY_REQUEST, {
            'proposal_id': proposal_id,
        }, self.session_key))


if __name__ == "__main__":
    import threading

    print("Network Sync Test")

    server = SyncServer()
    server.on_event('sync_received', lambda d: print(f"Server got sync: {d['blocks']} blocks, valid={d['valid']}"))
    server.on_event('emergency', lambda d: print(f"EMERGENCY: {d}"))
    server.start()
    time.sleep(0.5)

    client = SyncClient()
    if client.connect():
        print("Client connected!")
        # Simulate chain sync
        fake_chain = [{'index':0,'timestamp':'2024-01-01T00:00:00','vehicle_id':'TEST',
                       'telemetry_hash_sha3':'abc','event_hash_sha3':'def',
                       'previous_hash':'0'*64,'block_hash':'genesis'}]
        resp = client.sync_chain(fake_chain)
        print(f"Sync response: {resp}")
        client.disconnect()
    else:
        print("Could not connect to server")
    server.stop()
    print("Network test complete.")

