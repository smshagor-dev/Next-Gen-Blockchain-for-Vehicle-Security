# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Hardware -> Blockchain bridge.

Receives telemetry from:
1) Arduino serial JSON stream
2) Raspberry Pi TCP JSON stream

Then pushes into SmartCar blockchain pipeline (with edge/PoA/DID/ZKP/etc).
"""

import json
import os
import socket
import time
from datetime import datetime, timezone
from typing import Optional

from env_config import load_project_env_once, get_env, get_int, get_bool
from blockchain import SmartCarBlockchain, TelemetryData
from hardware_actuation_safety import BenchActuationGate
from hardware_transport_security import (
    AuthenticatedLineFramer,
    HardwareEnvelopeVerifier,
    HardwareTransportError,
    build_authenticated_envelope,
    build_safe_stop_payload,
    encode_authenticated_envelope,
    parse_device_registry,
    validate_plaintext_hardware_host,
)

load_project_env_once()

try:
    import serial  # type: ignore
except Exception:
    serial = None

try:
    import can  # type: ignore
except Exception:
    can = None


def _now():
    return datetime.now(timezone.utc).isoformat()


def to_telemetry(pkt: dict) -> TelemetryData:
    return TelemetryData(
        speed=float(pkt.get("speed", 0.0)),
        acceleration=float(pkt.get("acceleration", 0.0)),
        fuel_level=float(pkt.get("fuel_level", 100.0)),
        battery_voltage=float(pkt.get("battery_voltage", 12.6)),
        engine_temp=float(pkt.get("engine_temp", 20.0)),
        gps_lat=float(pkt.get("gps_lat", 0.0)),
        gps_lon=float(pkt.get("gps_lon", 0.0)),
        obstacle_distance=float(pkt.get("obstacle_distance", 999.0)),
        emergency_brake_active=bool(pkt.get("emergency_brake_active", False)),
        steering_angle=float(pkt.get("steering_angle", 0.0)),
        brake_pressure=float(pkt.get("brake_pressure", 0.0)),
        throttle_position=float(pkt.get("throttle_position", 0.0)),
        rpm=float(pkt.get("rpm", 0.0)),
        odometer=float(pkt.get("odometer", 0.0)),
        driver_heart_rate_bpm=float(pkt.get("driver_heart_rate_bpm", 72.0)),
        driver_drowsiness_score=float(pkt.get("driver_drowsiness_score", 0.0)),
        driver_unwell=bool(pkt.get("driver_unwell", False)),
        timestamp=str(pkt.get("timestamp", _now())),
    )


class GlobalTelemetryBudget:
    """Bound aggregate authenticated ledger mutations across TCP sessions.

    Single-process monotonic token bucket; not a distributed or durable quota.
    A rejected frame never reaches ledger mutation or remote actuation.
    """

    def __init__(self, rate_per_sec: int, burst: int, *, clock=None):
        self.rate = max(1, min(10000, int(rate_per_sec)))
        self.burst = max(1, min(10000, int(burst)))
        self.clock = clock or time.monotonic
        self.tokens = float(self.burst)
        self.last = self.clock()

    def claim(self) -> bool:
        now = self.clock()
        elapsed = max(0.0, now - self.last)
        self.last = now
        self.tokens = min(float(self.burst), self.tokens + elapsed * self.rate)
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


class AuthenticatedPiTelemetrySession:
    """Bind each connection to one enrolled identity, authenticating before mutation.

    The verifier and replay cache are shared across sessions by the server;
    the per-session framer is reset on disconnect. No legacy raw JSON fallback.
    """

    def __init__(self, verifier: HardwareEnvelopeVerifier):
        self.verifier = verifier
        self.framer = AuthenticatedLineFramer(verifier.max_frame_bytes)
        self.device_id = None

    def receive(self, data: bytes):
        verified = []
        for frame in self.framer.feed(data):
            item = self.verifier.verify(
                frame, expected_kind="TELEMETRY", expected_device_id=self.device_id
            )
            self.device_id = item.device_id
            verified.append(item)
        return verified


class SafeModeActuatorDispatcher:
    """Dispatch hardware stop commands when blockchain safe mode is activated."""

    def __init__(self, gate: Optional[BenchActuationGate] = None):
        self.gate = gate if gate is not None else BenchActuationGate()
        # Opt in explicitly; never energize an actuator just by starting bridge.
        self.enabled = get_bool("SMARTCAR_HARD_STOP_ENABLED", False)
        self._last_sent_at = 0.0
        self._cooldown_sec = 0.8
        self.ecu_gateway = ECUCommandGateway(gate=self.gate)

    def _should_send(self, bc: SmartCarBlockchain, block) -> bool:
        if not self.enabled or not self.gate.is_armed():
            return False
        now = time.time()
        if now - self._last_sent_at < self._cooldown_sec:
            return False
        return bool(getattr(bc, "safe_mode_active", False) or getattr(block, "safe_mode_activated", False))

    def maybe_send_arduino(
        self, ser, bc: SmartCarBlockchain, block, *,
        device_id: str, device_secret: str,
    ):
        if not self._should_send(bc, block):
            return
        try:
            payload = build_safe_stop_payload(block_index=getattr(block, "index", -1))
            envelope = build_authenticated_envelope(
                device_id, device_secret, "COMMAND", payload
            )
            ser.write(encode_authenticated_envelope(envelope))
            self._last_sent_at = time.time()
            print("[ACTUATOR] Signed SAFE_MODE_STOP sent to Arduino bench node")
        except (OSError, HardwareTransportError) as e:
            print(f"[ACTUATOR] Arduino command rejected: {e}")
            return
        self.ecu_gateway.send_safe_mode_stop(block_index=getattr(block, "index", -1))

    def maybe_send_pi(
        self,
        conn,
        bc: SmartCarBlockchain,
        block,
        *,
        device_id: str,
        device_secret: str,
    ):
        if not self._should_send(bc, block):
            return
        try:
            payload = build_safe_stop_payload(block_index=getattr(block, "index", -1))
            envelope = build_authenticated_envelope(
                device_id, device_secret, "COMMAND", payload
            )
            conn.sendall(encode_authenticated_envelope(envelope))
            self._last_sent_at = time.time()
            print("[ACTUATOR] Signed SAFE_MODE_STOP sent to Pi bench node")
        except (OSError, HardwareTransportError) as e:
            print(f"[ACTUATOR] Pi command rejected: {e}")
            return
        self.ecu_gateway.send_safe_mode_stop(block_index=getattr(block, "index", -1))


class ECUCommandGateway:
    """Send hard-stop command to ECU over CAN or serial fallback."""

    def __init__(self, gate: Optional[BenchActuationGate] = None):
        self.gate = gate if gate is not None else BenchActuationGate()
        self.enabled = get_bool("SMARTCAR_ECU_CONTROL_ENABLED", False)
        self.mode = get_env("SMARTCAR_ECU_MODE", "can").strip().lower()
        self._can_bus = None
        self._ser = None
        self._init_ok = False
        if self.enabled and self.gate.is_armed():
            self._init_transport()

    def _init_transport(self):
        if self.mode == "can":
            # Never downgrade a failed CAN transport to unsigned serial actuation.
            self._init_can()
        elif self.mode == "serial":
            # No authenticated ECU serial receiver protocol exists yet.
            print("[ECU] unsigned serial actuation disabled")
            self._init_ok = False
        else:
            print("[ECU] unsupported transport; actuation disabled")
            self._init_ok = False

    def _init_can(self):
        if can is None:
            print("[ECU] python-can not installed; CAN actuation unavailable")
            return
        channel = get_env("SMARTCAR_ECU_CAN_CHANNEL", "can0")
        bustype = get_env("SMARTCAR_ECU_CAN_BUSTYPE", "socketcan")
        bitrate = get_int("SMARTCAR_ECU_CAN_BITRATE", 500000)
        try:
            self._can_bus = can.interface.Bus(channel=channel, interface=bustype, bitrate=bitrate)
            self._init_ok = True
            print(f"[ECU] CAN connected channel={channel} bustype={bustype} bitrate={bitrate}")
        except Exception as e:
            print(f"[ECU] CAN init failed: {e}")
            self._can_bus = None
            self._init_ok = False

    def _init_serial(self):
        if serial is None:
            print("[ECU] pyserial not installed; ECU serial unavailable")
            return
        port = get_env("SMARTCAR_ECU_SERIAL_PORT", "COM5")
        baud = get_int("SMARTCAR_ECU_SERIAL_BAUD", 115200)
        try:
            self._ser = serial.Serial(port=port, baudrate=baud, timeout=0.2)
            self._init_ok = True
            print(f"[ECU] Serial connected port={port} baud={baud}")
        except Exception as e:
            self._ser = None
            self._init_ok = False
            print(f"[ECU] Serial init failed: {e}")

    def send_safe_mode_stop(self, block_index: int = -1):
        # CAN payloads have only an additive checksum, not receiver-verified
        # authentication or replay protection. Never actuate a vehicle from
        # this prototype until a separately reviewed ECU protocol exists.
        # Local hardwired emergency control is outside this software path.
        if self.mode == "can":
            print("[ECU] CAN actuation disabled: authenticated receiver protocol missing")
            return
        if not self.enabled or not self._init_ok or not self.gate.is_armed():
            return
        if self.mode == "can":
            self._send_can_safe_stop(block_index)
            return
        # Unsigned serial ECU actuation is deliberately unavailable.

    def _send_can_safe_stop(self, block_index: int):
        if self._can_bus is None:
            return
        arbitration_id = int(get_env("SMARTCAR_ECU_CAN_ARB_ID", "0x18FF50E5"), 16)
        throttle_cut = 0
        brake = 100
        ignition_cut = 1
        block_low = block_index & 0xFF
        block_high = (block_index >> 8) & 0xFF
        checksum = (0xA5 + throttle_cut + brake + ignition_cut + block_low + block_high) & 0xFF
        payload = [0xA5, 0x5A, throttle_cut, brake, ignition_cut, block_low, block_high, checksum]
        try:
            msg = can.Message(arbitration_id=arbitration_id, data=payload, is_extended_id=True)
            self._can_bus.send(msg, timeout=0.2)
            print(f"[ECU] SAFE_MODE_STOP sent over CAN id={hex(arbitration_id)} block={block_index}")
        except Exception as e:
            print(f"[ECU] CAN send failed: {e}")

    def _send_serial_safe_stop(self, block_index: int):
        # Unsigned serial ECU actuation is deliberately disabled.
        return


def run_arduino_mode(bc: SmartCarBlockchain):
    """Enrolled-device authenticated serial ingress; no unsigned JSON fallback.

    A framing or verification error quarantines the port. Local independent
    emergency controls are not routed through this ingestion loop.
    """
    if not serial:
        raise RuntimeError("pyserial not installed. Install with: pip install pyserial")

    port = get_env("SMARTCAR_HW_SERIAL_PORT", "COM3")
    baud = get_int("SMARTCAR_HW_SERIAL_BAUD", 115200)
    device_keys = parse_device_registry(get_env("SMARTCAR_HW_DEVICE_KEYS_JSON", "{}"))
    verifier = HardwareEnvelopeVerifier(
        device_keys,
        max_frame_bytes=get_int("SMARTCAR_HW_MAX_FRAME_BYTES", 4096),
        replay_window_sec=get_int("SMARTCAR_HW_REPLAY_WINDOW_SEC", 15),
        replay_cache_entries=get_int("SMARTCAR_HW_REPLAY_CACHE_ENTRIES", 2048),
    )
    session = AuthenticatedPiTelemetrySession(verifier)
    print(f"[HW BRIDGE] authenticated Arduino serial mode: {port} @ {baud}")
    try:
        ser = serial.Serial(port=port, baudrate=baud, timeout=1)
    except Exception as e:
        raise RuntimeError(f"Could not open serial port '{port}': {e}") from e

    # Remote commands remain subject to an independent bench interlock.
    actuator = SafeModeActuatorDispatcher()
    # A silent or trickle-fed serial peer must not monopolize the bridge forever.
    idle_timeout = max(1, min(30, get_int("SMARTCAR_HW_IDLE_TIMEOUT_SEC", 5)))
    max_session_sec = max(5, min(600, get_int("SMARTCAR_HW_MAX_SESSION_SEC", 120)))
    deadline = time.monotonic() + max_session_sec
    last_progress = time.monotonic()
    try:
        while time.monotonic() < deadline:
            if time.monotonic() - last_progress >= idle_timeout:
                raise RuntimeError("Arduino serial idle timeout; port quarantined")
            # Bounded read, including for a peer that never sends a newline.
            chunk = ser.read(1024)
            if not chunk:
                continue
            last_progress = time.monotonic()
            try:
                verified = session.receive(chunk)
            except HardwareTransportError as exc:
                print(f"[HW BRIDGE] quarantined Arduino serial input: {exc.reason}")
                raise RuntimeError("Arduino serial authentication/framing failure") from exc
            for item in verified:
                tel = to_telemetry(item.payload)
                event = str(item.payload["event"])
                block = bc.push_telemetry(tel, event)
                print(f"[CHAIN] block={block.index} event={event}")
                actuator.maybe_send_arduino(
                    ser, bc, block,
                    device_id=item.device_id,
                    device_secret=verifier.device_secret(item.device_id),
                )
        raise RuntimeError("Arduino serial session lifetime exceeded; port quarantined")
    finally:
        ser.close()


def run_pi_mode(bc: SmartCarBlockchain):
    """Authenticated, bounded, bench-scoped Pi receiver (no raw JSON bypass)."""
    host = validate_plaintext_hardware_host(
        get_env("SMARTCAR_HW_BRIDGE_HOST", "127.0.0.1"),
        allow_private_lan=get_bool("SMARTCAR_HW_ALLOW_PLAINTEXT_PRIVATE_LAN", False),
    )
    port = get_int("SMARTCAR_HW_BRIDGE_PORT", 9901)
    # Startup fails closed if no independent enrolled Pi secrets are configured.
    device_keys = parse_device_registry(get_env("SMARTCAR_HW_DEVICE_KEYS_JSON", "{}"))
    verifier = HardwareEnvelopeVerifier(
        device_keys,
        max_frame_bytes=get_int("SMARTCAR_HW_MAX_FRAME_BYTES", 32 * 1024),
        replay_window_sec=get_int("SMARTCAR_HW_REPLAY_WINDOW_SEC", 15),
        replay_cache_entries=get_int("SMARTCAR_HW_REPLAY_CACHE_ENTRIES", 2048),
    )
    idle_timeout = max(1, min(30, get_int("SMARTCAR_HW_IDLE_TIMEOUT_SEC", 5)))
    max_session_sec = max(5, min(600, get_int("SMARTCAR_HW_MAX_SESSION_SEC", 120)))
    # A fully authenticated peer can still flood ledger writes; bound work
    # per connection independently of the framer byte and time limits.
    max_frames = max(1, min(10000, get_int("SMARTCAR_HW_MAX_FRAMES_PER_SESSION", 256)))
    global_budget = GlobalTelemetryBudget(
        get_int("SMARTCAR_HW_GLOBAL_FRAMES_PER_SEC", 32),
        get_int("SMARTCAR_HW_GLOBAL_FRAME_BURST", 64),
    )
    # Charge admission before parsing or MAC verification, including failed
    # handshakes and repeated reconnects. Keep this separate from the
    # authenticated ledger mutation budget.
    admission_budget = GlobalTelemetryBudget(
        get_int("SMARTCAR_HW_ACCEPTS_PER_SEC", 4),
        get_int("SMARTCAR_HW_ACCEPT_BURST", 8),
    )
    auth_timeout = max(1, min(15, get_int("SMARTCAR_HW_AUTH_TIMEOUT_SEC", 3)))
    actuator = SafeModeActuatorDispatcher()
    print(f"[HW BRIDGE] Authenticated Pi TCP mode listening on {host}:{port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(4)
        while True:
            conn, addr = srv.accept()
            print(f"[HW BRIDGE] Pi connected: {addr[0]}:{addr[1]}")
            with conn:
                if not admission_budget.claim():
                    print("[HW BRIDGE] rejected connection: admission budget exceeded")
                    continue
                conn.settimeout(idle_timeout)
                session = AuthenticatedPiTelemetrySession(verifier)
                authentication_deadline = time.monotonic() + auth_timeout
                accepted_frames = 0
                deadline = time.monotonic() + max_session_sec
                try:
                    while time.monotonic() < deadline:
                        # Slowloris peers cannot keep the unauthenticated
                        # session open by sending partial bytes indefinitely.
                        if session.device_id is None:
                            remaining = authentication_deadline - time.monotonic()
                            if remaining <= 0:
                                raise HardwareTransportError("HW_AUTH_DEADLINE_EXCEEDED")
                            conn.settimeout(min(float(idle_timeout), remaining))
                        data = conn.recv(4096)
                        if not data:
                            break
                        # Verify MAC, freshness, replay nonce, schema, and per-
                        # connection identity before *any* ledger/actuation side effect.
                        for item in session.receive(data):
                            # Restore normal idle timeout after first valid MAC.
                            if accepted_frames == 0:
                                conn.settimeout(idle_timeout)
                            if accepted_frames >= max_frames:
                                raise HardwareTransportError("HW_SESSION_FRAME_BUDGET_EXCEEDED", authenticated=True)
                            if not global_budget.claim():
                                raise HardwareTransportError("HW_GLOBAL_FRAME_BUDGET_EXCEEDED", authenticated=True)
                            accepted_frames += 1
                            tel = to_telemetry(item.payload)
                            event = str(item.payload["event"])
                            block = bc.push_telemetry(tel, event)
                            print(f"[CHAIN] block={block.index} event={event}")
                            actuator.maybe_send_pi(
                                conn, bc, block,
                                device_id=item.device_id,
                                device_secret=verifier.device_secret(item.device_id),
                            )
                except HardwareTransportError as exc:
                    print(f"[HW BRIDGE] rejected Pi frame: {exc.reason}")
                except socket.timeout:
                    print("[HW BRIDGE] Pi connection closed after idle timeout")
                except OSError:
                    print("[HW BRIDGE] Pi connection ended after network error")
            print("[HW BRIDGE] Pi disconnected")

def main():
    vehicle_id = get_env("SMARTCAR_VEHICLE_ID", "SMARTCAR_VIN_2024_BD_XYZ789")
    password = get_env("SMARTCAR_PASSWORD", "SmartCarSecretKey2024!@#")
    auth_token = get_env("SMARTCAR_AUTH_TOKEN", "SECURE_AUTH_TOKEN_SHA3_2024")
    chain_file = get_env("SMARTCAR_HW_CHAIN_FILE", "logs/blockchain_hardware.json")
    mode = get_env("SMARTCAR_HW_MODE", "arduino").strip().lower()

    bc = SmartCarBlockchain(
        vehicle_id=vehicle_id,
        password=password,
        auth_token=auth_token,
        chain_file=chain_file
    )
    bc.authenticate(auth_token)
    bc.start_engine()

    print(f"[HW BRIDGE] mode={mode} chain_file={chain_file}")
    try:
        if mode == "pi":
            run_pi_mode(bc)
        else:
            run_arduino_mode(bc)
    except RuntimeError as e:
        print(f"[HW BRIDGE] {e}")
    except KeyboardInterrupt:
        pass
    finally:
        bc.stop_engine()
        bc.save()
        print("[HW BRIDGE] stopped and chain saved")


if __name__ == "__main__":
    main()

