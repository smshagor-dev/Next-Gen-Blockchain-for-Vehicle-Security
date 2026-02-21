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

from env_config import load_project_env_once, get_env, get_int
from blockchain import SmartCarBlockchain, TelemetryData

load_project_env_once()

try:
    import serial  # type: ignore
except Exception:
    serial = None


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
        timestamp=str(pkt.get("timestamp", _now())),
    )


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


def run_pi_mode(bc: SmartCarBlockchain):
    host = get_env("SMARTCAR_HW_BRIDGE_HOST", "127.0.0.1")
    port = get_int("SMARTCAR_HW_BRIDGE_PORT", 9901)
    print(f"[HW BRIDGE] Raspberry Pi TCP mode listening on {host}:{port}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(4)

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

