# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
V2X protocol for SmartCar research demo.

Supports:
- V2V: Vehicle telemetry beacon exchange
- V2I: Infrastructure signal broadcast
"""

import json
import socket
import threading
import time
import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Callable, Dict, Optional

try:
    from env_config import load_project_env_once, get_env, get_int
except Exception:
    from env_config import load_project_env_once, get_env, get_int

load_project_env_once()
logger = logging.getLogger("SmartCarV2X")


def _now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _make_nonce(seed: str) -> str:
    """Generate short per-message nonce."""
    return hashlib.sha3_256(f"{seed}|{time.time()}".encode()).hexdigest()[:16]


class V2XMessageType:
    HELLO = "HELLO"
    HELLO_ACK = "HELLO_ACK"
    V2V_TELEMETRY = "V2V_TELEMETRY"
    V2I_SIGNAL = "V2I_SIGNAL"
    ALERT = "ALERT"
    PING = "PING"
    PONG = "PONG"


def create_message(msg_type: str, sender_id: str, sender_type: str, payload: Dict) -> str:
    """Create one newline-delimited V2X JSON message."""
    msg = {
        "type": msg_type,
        "sender_id": sender_id,
        "sender_type": sender_type,
        "timestamp": _now(),
        "nonce": _make_nonce(sender_id + msg_type),
        "payload": payload,
    }
    return json.dumps(msg, sort_keys=True) + "\n"


def parse_message(raw: str) -> Optional[Dict]:
    """Parse one V2X JSON line safely."""
    try:
        return json.loads(raw.strip())
    except Exception:
        return None


class V2XHub:
    def __init__(self, host: str = None, port: int = None):
        """Initialize V2X hub socket state."""
        self.host = host or get_env("SMARTCAR_V2X_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_V2X_PORT", 9988)
        self._running = False
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._clients: Dict[socket.socket, Dict] = {}

    def start(self):
        """Start V2X hub server and accept loop."""
        if self._running:
            return
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.host, self.port))
            self._sock.listen(32)
            self._sock.settimeout(1.0)
        except OSError:
            self._running = False
            try:
                self._sock.close()
            except Exception as e:
                logger.debug("V2X hub socket close after bind failure: %s", e)
            raise
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        """Stop hub and close connected sockets."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception as e:
                logger.debug("V2X hub main socket close error: %s", e)
        with self._lock:
            sockets = list(self._clients.keys())
            self._clients.clear()
        for s in sockets:
            try:
                s.close()
            except Exception as e:
                logger.debug("V2X hub client socket close error: %s", e)

    def _accept_loop(self):
        """Accept clients and start per-client loops."""
        while self._running:
            try:
                conn, _addr = self._sock.accept()
                conn.settimeout(1.0)
                with self._lock:
                    self._clients[conn] = {"node_id": "unknown", "node_type": "unknown"}
                threading.Thread(target=self._client_loop, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.warning("V2X accept loop socket error", exc_info=True)
                    continue
                break
            except Exception:
                if self._running:
                    logger.exception("V2X accept loop unexpected error")
                    continue

    def _client_loop(self, conn: socket.socket):
        """Receive and route messages from one client."""
        buf = ""
        try:
            while self._running:
                try:
                    chunk = conn.recv(4096).decode(errors="replace")
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if not line.strip():
                        continue
                    msg = parse_message(line)
                    if not msg:
                        continue
                    self._handle_msg(conn, msg)
        finally:
            with self._lock:
                self._clients.pop(conn, None)
            try:
                conn.close()
            except Exception as e:
                logger.debug("V2X client socket close error: %s", e)

    def _handle_msg(self, conn: socket.socket, msg: Dict):
        """Handle HELLO/PING locally or broadcast payload."""
        mtype = msg.get("type", "")
        sender_id = msg.get("sender_id", "unknown")
        sender_type = msg.get("sender_type", "unknown")
        if mtype == V2XMessageType.HELLO:
            with self._lock:
                if conn in self._clients:
                    self._clients[conn]["node_id"] = sender_id
                    self._clients[conn]["node_type"] = sender_type
            ack = create_message(
                V2XMessageType.HELLO_ACK,
                sender_id="v2x_hub",
                sender_type="infrastructure",
                payload={"status": "CONNECTED", "hub_time": _now()},
            )
            try:
                conn.sendall(ack.encode())
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                logger.warning("Failed to send HELLO_ACK to %s", sender_id, exc_info=True)
                pass
            return
        if mtype == V2XMessageType.PING:
            pong = create_message(
                V2XMessageType.PONG,
                sender_id="v2x_hub",
                sender_type="infrastructure",
                payload={"ok": True},
            )
            try:
                conn.sendall(pong.encode())
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                logger.warning("Failed to send PONG to %s", sender_id, exc_info=True)
                pass
            return

        self._broadcast(msg, exclude=conn)

    def _broadcast(self, msg: Dict, exclude: Optional[socket.socket] = None):
        """Broadcast message to all connected nodes except sender."""
        payload = (json.dumps(msg, sort_keys=True) + "\n").encode()
        with self._lock:
            targets = list(self._clients.keys())
        for s in targets:
            if exclude is not None and s == exclude:
                continue
            try:
                s.sendall(payload)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                with self._lock:
                    self._clients.pop(s, None)
                try:
                    s.close()
                except Exception as e:
                    logger.debug("V2X broadcast target close error: %s", e)


class V2XNode:
    def __init__(
        self,
        node_id: str,
        node_type: str,
        host: str = None,
        port: int = None,
        on_message: Optional[Callable[[Dict], None]] = None,
    ):
        """Initialize V2X node client with callback hook."""
        self.node_id = node_id
        self.node_type = node_type
        self.host = host or get_env("SMARTCAR_V2X_HOST", "127.0.0.1")
        self.port = port or get_int("SMARTCAR_V2X_PORT", 9988)
        self.on_message = on_message
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._lock = threading.Lock()
        self._recv_thread: Optional[threading.Thread] = None

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self, timeout: float = 3.0) -> bool:
        """Connect node to hub and complete HELLO handshake."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(timeout)
            self._sock.connect((self.host, self.port))
            self._sock.settimeout(1.0)
            hello = create_message(
                V2XMessageType.HELLO,
                sender_id=self.node_id,
                sender_type=self.node_type,
                payload={"node_version": "1.0"},
            )
            self._sock.sendall(hello.encode())
            raw = self._recv_line()
            msg = parse_message(raw) if raw else None
            if not msg or msg.get("type") != V2XMessageType.HELLO_ACK:
                self.disconnect()
                return False
            self._connected = True
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._recv_thread.start()
            return True
        except Exception:
            logger.exception("V2X node connect failed (%s:%s)", self.host, self.port)
            self.disconnect()
            return False

    def disconnect(self):
        """Disconnect node socket."""
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except Exception as e:
                logger.debug("V2X node socket close error: %s", e)
            self._sock = None

    def _recv_line(self) -> Optional[str]:
        """Read one newline-delimited message."""
        if not self._sock:
            return None
        buf = ""
        while "\n" not in buf:
            try:
                chunk = self._sock.recv(4096).decode(errors="replace")
            except socket.timeout:
                continue
            except Exception:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf.split("\n", 1)[0]

    def _recv_loop(self):
        """Receive loop for async messages from hub."""
        if not self._sock:
            return
        buf = ""
        while self._connected:
            try:
                chunk = self._sock.recv(4096).decode(errors="replace")
            except socket.timeout:
                continue
            except Exception:
                self._connected = False
                break
            if not chunk:
                self._connected = False
                break
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if not line.strip():
                    continue
                msg = parse_message(line)
                if msg and self.on_message:
                    try:
                        self.on_message(msg)
                    except Exception:
                        logger.exception("V2X on_message callback error")
                        continue

    def send(self, msg_type: str, payload: Dict) -> bool:
        """Send one message to hub."""
        if not self._connected or not self._sock:
            return False
        data = create_message(msg_type, self.node_id, self.node_type, payload).encode()
        with self._lock:
            try:
                self._sock.sendall(data)
                return True
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                self._connected = False
                return False

    def send_v2v_telemetry(self, speed: float, lat: float, lon: float, heading: float = 0.0) -> bool:
        """Send compact V2V telemetry beacon."""
        return self.send(V2XMessageType.V2V_TELEMETRY, {
            "speed": round(float(speed), 2),
            "lat": round(float(lat), 6),
            "lon": round(float(lon), 6),
            "heading": round(float(heading), 2),
        })

    def send_v2i_signal(self, intersection_id: str, signal_state: str, ttl_sec: int = 10,
                        extra_payload: Optional[Dict] = None) -> bool:
        """Send V2I infrastructure command payload."""
        payload = {
            "intersection_id": intersection_id,
            "signal_state": signal_state,
            "ttl_sec": int(ttl_sec),
        }
        if extra_payload:
            payload.update(extra_payload)
        return self.send(V2XMessageType.V2I_SIGNAL, payload)


if __name__ == "__main__":
    print("Starting V2X hub on 127.0.0.1:9988")
    hub = V2XHub()
    hub.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        hub.stop()
        print("V2X hub stopped.")

