# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Raspberry Pi hardware telemetry node.

Publishes JSON telemetry over TCP for blockchain bridge ingestion.
"""

import json
import math
import random
import socket
import time
import select
from datetime import datetime, timezone
from typing import Optional

try:
    import RPi.GPIO as GPIO  # type: ignore
except Exception:
    GPIO = None

try:
    import cv2  # type: ignore
except Exception:
    cv2 = None

from env_config import load_project_env_once, get_env, get_int, get_float

load_project_env_once()

try:
    import serial  # type: ignore
except Exception:
    serial = None


class HeartRateSensorSerial:
    """Read BPM from a dedicated biometric MCU over serial (plain number per line)."""

    def __init__(self, port: str, baud: int):
        self.port = port
        self.baud = baud
        self._ser = None
        if serial:
            try:
                self._ser = serial.Serial(port=port, baudrate=baud, timeout=0.05)
            except Exception:
                self._ser = None

    @property
    def ready(self) -> bool:
        return self._ser is not None

    def read_bpm(self) -> Optional[float]:
        if not self._ser:
            return None
        try:
            line = self._ser.readline().decode(errors="ignore").strip()
            if not line:
                return None
            bpm = float(line)
            if 20.0 <= bpm <= 240.0:
                return bpm
        except Exception:
            return None
        return None


class DrowsinessEyeClosureDetector:
    """
    Practical real-time drowsiness proxy without heavy landmark model:
    estimate sustained eye closure ratio from face ROI luminance band.
    """

    def __init__(self, camera_index: int = 0):
        self.enabled = cv2 is not None
        self._cap = None
        self._face = None
        self._score = 0.0
        if not self.enabled:
            return
        self._cap = cv2.VideoCapture(camera_index)
        if not self._cap or not self._cap.isOpened():
            self.enabled = False
            return
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        self._face = cv2.CascadeClassifier(cascade_path)
        if self._face.empty():
            self.enabled = False

    def read_score(self) -> Optional[float]:
        if not self.enabled or not self._cap:
            return None
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return None
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self._face.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(60, 60))
        if len(faces) == 0:
            self._score = min(1.0, self._score + 0.03)
            return self._score
        x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
        # Approximate eye band in upper face.
        eye_band = gray[y + int(0.18 * h): y + int(0.40 * h), x + int(0.12 * w): x + int(0.88 * w)]
        if eye_band.size == 0:
            return None
        mean_luma = float(eye_band.mean())
        # Lower contrast/luma often indicates closed eyes in IR/low-light cabin cam.
        closed_like = mean_luma < 65.0
        self._score = min(1.0, self._score + 0.08) if closed_like else max(0.0, self._score - 0.06)
        return self._score

    def cleanup(self):
        if self._cap:
            self._cap.release()


class SafetyActuator:
    """GPIO output for fail-safe stop (relay/ignition cut)."""

    def __init__(self, brake_pin: int = 17, ignition_cut_pin: int = 27):
        self.brake_pin = brake_pin
        self.ignition_cut_pin = ignition_cut_pin
        self.ready = False
        if GPIO:
            try:
                GPIO.setmode(GPIO.BCM)
                GPIO.setup(self.brake_pin, GPIO.OUT)
                GPIO.setup(self.ignition_cut_pin, GPIO.OUT)
                GPIO.output(self.brake_pin, False)
                GPIO.output(self.ignition_cut_pin, False)
                self.ready = True
            except Exception:
                self.ready = False

    def safe_stop(self):
        if not self.ready:
            return
        GPIO.output(self.brake_pin, True)
        GPIO.output(self.ignition_cut_pin, True)

    def release(self):
        if not self.ready:
            return
        GPIO.output(self.brake_pin, False)
        GPIO.output(self.ignition_cut_pin, False)


class UltrasonicHC_SR04:
    def __init__(self, trig_pin: int = 23, echo_pin: int = 24):
        self.trig_pin = trig_pin
        self.echo_pin = echo_pin
        self._ready = False
        if GPIO:
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(self.trig_pin, GPIO.OUT)
            GPIO.setup(self.echo_pin, GPIO.IN)
            GPIO.output(self.trig_pin, False)
            time.sleep(0.2)
            self._ready = True

    @property
    def ready(self) -> bool:
        return self._ready

    def read_distance_m(self, timeout_s: float = 0.04) -> float:
        if not self._ready:
            # Fallback for development on non-Pi machine.
            return random.uniform(2.0, 150.0)

        GPIO.output(self.trig_pin, True)
        time.sleep(0.00001)
        GPIO.output(self.trig_pin, False)

        start_wait = time.time()
        pulse_start = time.time()
        while GPIO.input(self.echo_pin) == 0:
            pulse_start = time.time()
            if pulse_start - start_wait > timeout_s:
                return 999.0

        pulse_end = pulse_start
        while GPIO.input(self.echo_pin) == 1:
            pulse_end = time.time()
            if pulse_end - pulse_start > timeout_s:
                return 999.0

        pulse_duration = pulse_end - pulse_start
        # speed of sound: 34300 cm/s; /2 for return
        distance_cm = (pulse_duration * 34300) / 2
        return max(0.2, min(999.0, distance_cm / 100.0))

    def cleanup(self):
        if GPIO:
            GPIO.cleanup()


class PiTelemetryNode:
    def __init__(self, host: str = "127.0.0.1", port: int = 9901, interval_sec: float = 0.2):
        self.host = host
        self.port = port
        self.interval_sec = interval_sec
        self.sensor = UltrasonicHC_SR04()
        self.hr_sensor = HeartRateSensorSerial(
            port=get_env("SMARTCAR_BIOMETRIC_SERIAL_PORT", "/dev/ttyUSB0"),
            baud=get_int("SMARTCAR_BIOMETRIC_SERIAL_BAUD", 115200),
        )
        self.drowsiness = DrowsinessEyeClosureDetector(
            camera_index=get_int("SMARTCAR_DROWSINESS_CAMERA_INDEX", 0)
        )
        self.safe_actuator = SafetyActuator(
            brake_pin=get_int("SMARTCAR_PI_BRAKE_RELAY_PIN", 17),
            ignition_cut_pin=get_int("SMARTCAR_PI_IGNITION_CUT_PIN", 27),
        )
        self._sock = None
        self._odo = 0.0
        self._tick = 0.0
        self._last_hr = get_float("SMARTCAR_BIOMETRIC_FALLBACK_HR", 72.0)
        self._last_drowsy = 0.0

    def _connect(self):
        while True:
            try:
                self._sock = socket.create_connection((self.host, self.port), timeout=5.0)
                self._sock.setblocking(False)
                return
            except Exception:
                time.sleep(1.0)

    def _read_heart_rate(self) -> float:
        bpm = self.hr_sensor.read_bpm() if self.hr_sensor.ready else None
        if bpm is None:
            return self._last_hr
        self._last_hr = bpm
        return bpm

    def _read_drowsiness(self) -> float:
        score = self.drowsiness.read_score()
        if score is None:
            return self._last_drowsy
        self._last_drowsy = score
        return score

    def _recv_control_commands(self):
        if not self._sock:
            return
        try:
            ready, _, _ = select.select([self._sock], [], [], 0.0)
            if not ready:
                return
            data = self._sock.recv(4096)
            if not data:
                return
            for line in data.decode(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                cmd = json.loads(line)
                if str(cmd.get("cmd", "")).upper() == "SAFE_MODE_STOP":
                    self.safe_actuator.safe_stop()
        except Exception:
            return

    def _packet(self) -> dict:
        self._tick += self.interval_sec
        speed = max(0.0, 42.0 + 12.0 * math.sin(self._tick / 2.0))
        rpm = 1200 + speed * 35
        self._odo += speed / 3600.0 * self.interval_sec
        obstacle = self.sensor.read_distance_m()
        emergency = obstacle < 100.0
        hr = self._read_heart_rate()
        drowsy = self._read_drowsiness()
        unwell = (hr <= get_float("BIOMETRIC_HEART_RATE_LOW_BPM", 45.0) or
                  hr >= get_float("BIOMETRIC_HEART_RATE_HIGH_BPM", 140.0) or
                  drowsy >= get_float("BIOMETRIC_DROWSINESS_THRESHOLD", 0.80))
        return {
            "source": "raspberry_pi",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "speed": round(speed, 2),
            "acceleration": round(random.uniform(-1.2, 1.2), 2),
            "fuel_level": round(max(0.0, 90.0 - self._odo * 0.02), 2),
            "battery_voltage": round(13.7 + random.uniform(-0.05, 0.05), 3),
            "engine_temp": round(78.0 + random.uniform(-2.0, 2.0), 2),
            "gps_lat": 23.8103 + random.uniform(-0.0002, 0.0002),
            "gps_lon": 90.4125 + random.uniform(-0.0002, 0.0002),
            "obstacle_distance": round(obstacle, 2),
            "emergency_brake_active": emergency,
            "steering_angle": round(random.uniform(-6.0, 6.0), 2),
            "brake_pressure": 100.0 if emergency else round(max(0.0, 20.0 - speed * 0.1), 2),
            "throttle_position": round(min(100.0, 25.0 + speed * 0.5), 2),
            "rpm": round(rpm, 1),
            "odometer": round(self._odo, 5),
            "driver_heart_rate_bpm": round(hr, 2),
            "driver_drowsiness_score": round(drowsy, 3),
            "driver_unwell": bool(unwell),
            "event": "HW:PI:TELEMETRY",
        }

    def run(self):
        print(f"[PI NODE] Streaming telemetry -> {self.host}:{self.port}")
        self._connect()
        while True:
            pkt = self._packet()
            line = json.dumps(pkt, separators=(",", ":")) + "\n"
            try:
                self._sock.sendall(line.encode())
            except Exception:
                self._connect()
                continue
            self._recv_control_commands()
            time.sleep(self.interval_sec)


if __name__ == "__main__":
    node = PiTelemetryNode()
    try:
        node.run()
    finally:
        node.sensor.cleanup()
        node.drowsiness.cleanup()

