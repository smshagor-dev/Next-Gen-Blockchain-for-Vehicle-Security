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
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from env_config import load_project_env_once, get_env, get_int, get_bool
from blockchain import SmartCarBlockchain, TelemetryData
from bounded_tcp_admission import BoundedTCPAdmission
from hardware_actuation_safety import BenchActuationGate
from hardware_transport_deadlines import deadline_check, DeadlineExpired
from hardware_ingress_clock import verify_ingress_observation
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


def _finite_telemetry_number(value, field):
    """Reject non-finite and non-numeric signed telemetry before chain mutation."""
    import math
    # JSON numbers must remain numbers: strings, booleans and containers are
    # not valid authenticated sensor measurements, even if float() coerces them.
    if type(value) not in (int, float):
        raise ValueError(f"{field}: expected JSON number")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{field}: invalid numeric measurement") from exc
    if not math.isfinite(number):
        raise ValueError(f"{field}: non-finite numeric measurement")
    return number


def _strict_telemetry_bool(value, field):
    if type(value) is not bool:
        raise ValueError(f"{field}: expected boolean")
    return value



def _signed_observation_timestamp(value):
    """Require an explicit UTC observation time; never substitute ingestion time.

    Envelope MAC/freshness authenticates the transport message, not the
    observation's age. A device could sign old measurements with a fresh nonce.
    Keeping a strict observation timestamp allows downstream research to
    evaluate that age without silently inventing a current measurement.
    """
    if type(value) is not str or not 20 <= len(value) <= 40:
        raise ValueError("timestamp: explicit bounded UTC ISO-8601 string required")
    # Only canonical Z or explicit +00:00 are accepted. Offset conversion,
    # naive local clocks and arbitrary text cannot silently change semantics.
    if value.endswith("Z"):
        value_to_parse = value[:-1] + "+00:00"
    elif value.endswith("+00:00"):
        value_to_parse = value
    else:
        raise ValueError("timestamp: UTC timezone required")
    try:
        parsed = datetime.fromisoformat(value_to_parse)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("timestamp: invalid ISO-8601 UTC value") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("timestamp: UTC timezone required")
    # Require full date and time, explicit seconds, and disallow ISO shortcuts
    # (basic dates, comma fractions, etc.). Normalize only after validation.
    import re
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value):
        raise ValueError("timestamp: noncanonical observation timestamp")
    return parsed.astimezone(timezone.utc).isoformat()



def to_telemetry(pkt: dict) -> TelemetryData:
    # Safety-critical booleans must be explicitly supplied by an authenticated
    # sender. Missing fields must not silently become a safe/healthy reading.
    if type(pkt) is not dict:
        raise ValueError("telemetry: expected JSON object")
    for field in ("emergency_brake_active", "driver_unwell"):
        if field not in pkt:
            raise ValueError(f"{field}: required signed telemetry field")
    return TelemetryData(
        speed=_finite_telemetry_number(pkt.get("speed", 0.0), "speed"),
        acceleration=_finite_telemetry_number(pkt.get("acceleration", 0.0), "acceleration"),
        fuel_level=_finite_telemetry_number(pkt.get("fuel_level", 100.0), "fuel_level"),
        battery_voltage=_finite_telemetry_number(pkt.get("battery_voltage", 12.6), "battery_voltage"),
        engine_temp=_finite_telemetry_number(pkt.get("engine_temp", 20.0), "engine_temp"),
        gps_lat=_finite_telemetry_number(pkt.get("gps_lat", 0.0), "gps_lat"),
        gps_lon=_finite_telemetry_number(pkt.get("gps_lon", 0.0), "gps_lon"),
        obstacle_distance=_finite_telemetry_number(pkt.get("obstacle_distance", 999.0), "obstacle_distance"),
        emergency_brake_active=_strict_telemetry_bool(pkt.get("emergency_brake_active", False), "emergency_brake_active"),
        steering_angle=_finite_telemetry_number(pkt.get("steering_angle", 0.0), "steering_angle"),
        brake_pressure=_finite_telemetry_number(pkt.get("brake_pressure", 0.0), "brake_pressure"),
        throttle_position=_finite_telemetry_number(pkt.get("throttle_position", 0.0), "throttle_position"),
        rpm=_finite_telemetry_number(pkt.get("rpm", 0.0), "rpm"),
        odometer=_finite_telemetry_number(pkt.get("odometer", 0.0), "odometer"),
        driver_heart_rate_bpm=_finite_telemetry_number(pkt.get("driver_heart_rate_bpm", 72.0), "driver_heart_rate_bpm"),
        driver_drowsiness_score=_finite_telemetry_number(pkt.get("driver_drowsiness_score", 0.0), "driver_drowsiness_score"),
        driver_unwell=_strict_telemetry_bool(pkt.get("driver_unwell", False), "driver_unwell"),
        timestamp=_signed_observation_timestamp(pkt.get("timestamp")),
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
        # Shared by concurrent TCP handlers; protect the full refill/claim RMW.
        self._lock = threading.Lock()

    def claim(self) -> bool:
        with self._lock:
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
    """Fail-closed network command boundary.

    A ledger safe-mode event is evidence for a local alert, not authorization
    to send an actuator command to a remote Arduino/Pi. In particular, a
    sender-side MAC and a bench arming flag cannot establish receiver-side
    authorization, freshness, physical interlock state, or local emergency
    precedence. Physical emergency stop remains an independent local circuit.
    """

    def __init__(self, gate: Optional[BenchActuationGate] = None):
        self.gate = gate if gate is not None else BenchActuationGate()
        self.enabled = False
        self.ecu_gateway = ECUCommandGateway(gate=self.gate)

    def _should_send(self, bc: SmartCarBlockchain, block) -> bool:
        # Intentionally non-configurable until independently validated receiver
        # authorization and physical interlocks are implemented.
        return False

    def maybe_send_arduino(
        self, ser, bc: SmartCarBlockchain, block, *,
        device_id: str, device_secret: str,
    ):
        """Never send a network-originated stop command to an actuator."""
        return False

    def maybe_send_pi(
        self, conn, bc: SmartCarBlockchain, block, *,
        device_id: str, device_secret: str,
    ):
        """Never send a network-originated stop command to an actuator."""
        return False


class ECUCommandGateway:
    """Send hard-stop command to ECU over CAN or serial fallback."""

    def __init__(self, gate: Optional[BenchActuationGate] = None):
        self.gate = gate if gate is not None else BenchActuationGate()
        self.enabled = get_bool("SMARTCAR_ECU_CONTROL_ENABLED", False)
        self.mode = get_env("SMARTCAR_ECU_MODE", "can").strip().lower()
        self._can_bus = None
        self._ser = None
        self._init_ok = False
        # No receiver-authenticated CAN/serial command protocol exists.
        # Never initialize an ECU output bus, even with a bench interlock.
        # Local hardwired emergency stop is independent of this bridge.
        self._init_ok = False

    def _init_transport(self):
        """Fail closed: no receiver-authenticated ECU command protocol exists."""
        self._init_ok = False
        return False

    def _init_can(self):
        """Never open a CAN output interface from the remote telemetry bridge."""
        self._init_ok = False
        return False

    def _init_serial(self):
        """Never open an unsigned serial ECU output interface."""
        self._init_ok = False
        return False

    def send_safe_mode_stop(self, block_index: int = -1):
        """No remote stop actuation; physical local emergency stop remains independent.

        A signed network envelope or operator-controlled bench permit cannot
        authorize a CAN/serial command without an independently verified ECU
        receiver, nonce protocol, and physical safety interlock.
        """
        return False

    def _send_can_safe_stop(self, block_index: int):
        """Legacy direct-call path must not bypass receiver authorization."""
        return False

    def _send_serial_safe_stop(self, block_index: int):
        """Legacy direct-call path must not bypass receiver authorization."""
        return False


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
            ingress_monotonic = time.monotonic()
            ingress_utc = datetime.now(timezone.utc)
            last_progress = ingress_monotonic
            try:
                verified = session.receive(chunk)
            except HardwareTransportError as exc:
                print(f"[HW BRIDGE] quarantined Arduino serial input: {exc.reason}")
                raise RuntimeError("Arduino serial authentication/framing failure") from exc
            for item in verified:
                # A single serial read may contain several valid envelopes.
                # Verification and earlier ledger writes consume time; do not
                # admit later envelopes after the absolute session deadline.
                if time.monotonic() >= deadline:
                    raise RuntimeError("Arduino serial session lifetime exceeded; port quarantined")
                verify_ingress_observation(
                    item.payload.get("timestamp"),
                    received_utc=ingress_utc,
                    received_monotonic=ingress_monotonic,
                    commit_monotonic=time.monotonic(),
                    max_age_seconds=max(1, min(3600, get_int("SMARTCAR_HW_OBSERVATION_MAX_AGE_SEC", 15))),
                    max_future_skew_seconds=max(0, min(60, get_int("SMARTCAR_HW_OBSERVATION_FUTURE_SKEW_SEC", 2))),
                )
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
    # Cap total ingress bytes independently of signed-frame count. A peer
    # sending endless partial frames must not receive an unlimited CPU budget.
    max_session_bytes = max(4096, min(8 * 1024 * 1024, get_int("SMARTCAR_HW_MAX_SESSION_BYTES", 262144)))
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
    verifier_lock = threading.Lock()  # Replay nonce check-and-claim must be atomic.
    ledger_lock = threading.Lock()  # Chain mutations must be serialized.
    actuator_lock = threading.Lock()  # Dispatcher cooldown and outbound command state are shared.
    max_clients = max(1, min(64, get_int("SMARTCAR_HW_MAX_CLIENTS", 4)))
    print(f"[HW BRIDGE] Authenticated Pi TCP mode listening on {host}:{port}")

    def handle_client(conn):
            conn.settimeout(idle_timeout)
            session = AuthenticatedPiTelemetrySession(verifier)
            authentication_deadline = time.monotonic() + auth_timeout
            accepted_frames = 0
            # Per-connection accounting must start before the first recv.
            received_bytes = 0
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
                    # Also enforce the absolute session deadline at the
                    # blocking syscall, not only at the next loop iteration.
                    session_remaining = deadline - time.monotonic()
                    if session_remaining <= 0:
                        raise HardwareTransportError("HW_SESSION_DEADLINE_EXCEEDED")
                    if session.device_id is None:
                        conn.settimeout(min(float(idle_timeout), remaining, session_remaining))
                    else:
                        conn.settimeout(min(float(idle_timeout), session_remaining))
                    data = conn.recv(4096)
                    if not data:
                        break
                    ingress_monotonic = time.monotonic()
                    ingress_utc = datetime.now(timezone.utc)
                    received_bytes += len(data)
                    if received_bytes > max_session_bytes:
                        raise HardwareTransportError("HW_SESSION_BYTE_BUDGET_EXCEEDED")
                    # A complete signed frame arriving after the authentication
                    # deadline must not be admitted merely because recv began
                    # before the deadline. Likewise for session expiry.
                    received_at = time.monotonic()
                    try:
                        deadline_check(
                            received_at, session_deadline=deadline,
                            auth_deadline=authentication_deadline,
                            authenticated=session.device_id is not None,
                        )
                    except DeadlineExpired as exc:
                        raise HardwareTransportError(str(exc)) from exc
                    # Verify MAC, freshness, replay nonce, schema, and per-
                    # connection identity before *any* ledger/actuation side effect.
                    with verifier_lock:
                        verified_items = session.receive(data)
                    for item in verified_items:
                        # A single recv may contain many signed frames. MAC
                        # verification can itself consume the remaining
                        # session lifetime; recheck before EACH mutation.
                        # First authentication must also complete before
                        # its deadline, not merely before recv returns.
                        try:
                            deadline_check(
                                time.monotonic(),
                                session_deadline=deadline,
                                auth_deadline=authentication_deadline,
                                authenticated=accepted_frames > 0,
                            )
                        except DeadlineExpired as exc:
                            raise HardwareTransportError(str(exc)) from exc
                        # Restore normal idle timeout after first valid MAC.
                        if accepted_frames == 0:
                            conn.settimeout(idle_timeout)
                        if accepted_frames >= max_frames:
                            raise HardwareTransportError("HW_SESSION_FRAME_BUDGET_EXCEEDED", authenticated=True)
                        if not global_budget.claim():
                            raise HardwareTransportError("HW_GLOBAL_FRAME_BUDGET_EXCEEDED", authenticated=True)
                        accepted_frames += 1
                        verify_ingress_observation(
                            item.payload.get("timestamp"),
                            received_utc=ingress_utc,
                            received_monotonic=ingress_monotonic,
                            commit_monotonic=time.monotonic(),
                            max_age_seconds=max(1, min(3600, get_int("SMARTCAR_HW_OBSERVATION_MAX_AGE_SEC", 15))),
                            max_future_skew_seconds=max(0, min(60, get_int("SMARTCAR_HW_OBSERVATION_FUTURE_SKEW_SEC", 2))),
                        )
                        tel = to_telemetry(item.payload)
                        event = str(item.payload["event"])
                        with ledger_lock:
                            block = bc.push_telemetry(tel, event)
                        # Network sendall may block for the peer's socket timeout.
                        # Never hold the global chain lock while waiting on a peer.
                        # Remote bench actuation remains gated and independent of
                        # local hardwired emergency controls.
                        with actuator_lock:
                            actuator.maybe_send_pi(
                                conn, bc, block,
                                device_id=item.device_id,
                                device_secret=verifier.device_secret(item.device_id),
                            )
                        print(f"[CHAIN] block={block.index} event={event}")
            except HardwareTransportError as exc:
                print(f"[HW BRIDGE] rejected Pi frame: {exc.reason}")
            except (ValueError, TypeError, KeyError) as exc:
                print(f"[HW BRIDGE] rejected malformed authenticated telemetry: {type(exc).__name__}")
            except socket.timeout:
                print("[HW BRIDGE] Pi connection closed after idle timeout")
            except OSError:
                print("[HW BRIDGE] Pi connection ended after network error")

    admission = BoundedTCPAdmission(handle_client, max_clients=max_clients)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(max_clients)
        while True:
            conn, addr = srv.accept()
            if not admission_budget.claim():
                conn.close()
                continue
            admission.dispatch(conn)

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
        elif mode == "arduino":
            run_arduino_mode(bc)
        else:
            raise RuntimeError("Unsupported SMARTCAR_HW_MODE; expected pi or arduino")
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

