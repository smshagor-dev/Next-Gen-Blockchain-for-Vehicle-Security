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


class SafeModeActuatorDispatcher:
    """Dispatch hardware stop commands when blockchain safe mode is activated."""

    def __init__(self):
        self.enabled = get_bool("SMARTCAR_HARD_STOP_ENABLED", True)
        self._last_sent_at = 0.0
        self._cooldown_sec = 0.8
        self.ecu_gateway = ECUCommandGateway()

    def _should_send(self, bc: SmartCarBlockchain, block) -> bool:
        if not self.enabled:
            return False
        now = time.time()
        if now - self._last_sent_at < self._cooldown_sec:
            return False
        return bool(getattr(bc, "safe_mode_active", False) or getattr(block, "safe_mode_activated", False))

    def maybe_send_arduino(self, ser, bc: SmartCarBlockchain, block):
        if not self._should_send(bc, block):
            return
        cmd = {
            "cmd": "SAFE_MODE_STOP",
            "throttle": 0,
            "brake_pressure": 100,
            "ignition_cut": 1,
            "timestamp": _now(),
        }
        try:
            ser.write((json.dumps(cmd) + "\n").encode())
            self._last_sent_at = time.time()
            print("[ACTUATOR] SAFE_MODE_STOP sent to Arduino")
        except Exception as e:
            print(f"[ACTUATOR] Arduino command failed: {e}")
        self.ecu_gateway.send_safe_mode_stop(block_index=getattr(block, "index", -1))

    def maybe_send_pi(self, conn, bc: SmartCarBlockchain, block):
        if not self._should_send(bc, block):
            return
        cmd = {
            "cmd": "SAFE_MODE_STOP",
            "throttle": 0,
            "brake_pressure": 100,
            "ignition_cut": 1,
            "timestamp": _now(),
        }
        try:
            conn.sendall((json.dumps(cmd) + "\n").encode())
            self._last_sent_at = time.time()
            print("[ACTUATOR] SAFE_MODE_STOP sent to Pi node")
        except Exception as e:
            print(f"[ACTUATOR] Pi command failed: {e}")
        self.ecu_gateway.send_safe_mode_stop(block_index=getattr(block, "index", -1))


class ECUCommandGateway:
    """Send hard-stop command to ECU over CAN or serial fallback."""

    def __init__(self):
        self.enabled = get_bool("SMARTCAR_ECU_CONTROL_ENABLED", True)
        self.mode = get_env("SMARTCAR_ECU_MODE", "can").strip().lower()
        self._can_bus = None
        self._ser = None
        self._init_ok = False
        if self.enabled:
            self._init_transport()

    def _init_transport(self):
        if self.mode == "can":
            self._init_can()
            if self._init_ok:
                return
            self.mode = "serial"
        if self.mode == "serial":
            self._init_serial()

    def _init_can(self):
        if can is None:
            print("[ECU] python-can not installed, fallback to serial")
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
        if not self.enabled or not self._init_ok:
            return
        if self.mode == "can":
            self._send_can_safe_stop(block_index)
            return
        if self.mode == "serial":
            self._send_serial_safe_stop(block_index)

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
        if self._ser is None:
            return
        cmd = {
            "cmd": "ECU_SAFE_MODE_STOP",
            "throttle_cut": 1,
            "target_speed": 0,
            "brake_pressure": 100,
            "ignition_cut": 1,
            "block_index": block_index,
            "timestamp": _now(),
        }
        try:
            self._ser.write((json.dumps(cmd) + "\n").encode())
            print(f"[ECU] SAFE_MODE_STOP sent over serial block={block_index}")
        except Exception as e:
            print(f"[ECU] Serial send failed: {e}")


def run_arduino_mode(bc: SmartCarBlockchain):
    if not serial:
        raise RuntimeError("pyserial not installed. Install with: pip install pyserial")

    port = get_env("SMARTCAR_HW_SERIAL_PORT", "COM3")
    baud = get_int("SMARTCAR_HW_SERIAL_BAUD", 115200)
    print(f"[HW BRIDGE] Arduino serial mode: {port} @ {baud}")
    try:
        ser = serial.Serial(port=port, baudrate=baud, timeout=1)
    except Exception as e:
        raise RuntimeError(
            f"Could not open serial port '{port}'. "
            f"Set SMARTCAR_HW_SERIAL_PORT in .env to your Arduino port. Details: {e}"
        )
    actuator = SafeModeActuatorDispatcher()
    while True:
        line = ser.readline().decode(errors="ignore").strip()
        if not line:
            continue
        try:
            pkt = json.loads(line)
        except Exception:
            continue
        tel = to_telemetry(pkt)
        evt = str(pkt.get("event", "HW:ARDUINO:TELEMETRY"))
        b = bc.push_telemetry(tel, evt)
        print(f"[CHAIN] block={b.index} event={evt}")
        actuator.maybe_send_arduino(ser, bc, b)


def run_pi_mode(bc: SmartCarBlockchain):
    host = get_env("SMARTCAR_HW_BRIDGE_HOST", "127.0.0.1")
    port = get_int("SMARTCAR_HW_BRIDGE_PORT", 9901)
    print(f"[HW BRIDGE] Raspberry Pi TCP mode listening on {host}:{port}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(4)

    actuator = SafeModeActuatorDispatcher()
    while True:
        conn, addr = srv.accept()
        print(f"[HW BRIDGE] Pi connected: {addr[0]}:{addr[1]}")
        buf = ""
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buf += data.decode(errors="ignore")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        pkt = json.loads(line)
                    except Exception:
                        continue
                    tel = to_telemetry(pkt)
                    evt = str(pkt.get("event", "HW:PI:TELEMETRY"))
                    b = bc.push_telemetry(tel, evt)
                    print(f"[CHAIN] block={b.index} event={evt}")
                    actuator.maybe_send_pi(conn, bc, b)
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

