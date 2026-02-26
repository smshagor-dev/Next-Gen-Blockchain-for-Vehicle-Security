# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
SmartCar Sensor Simulation Module
- LIDAR/Radar obstacle detection (0-200m range)
- GPS simulation
- Engine telemetry
- Emergency brake controller
"""

import random
import math
import time
import threading
from dataclasses import dataclass
from typing import Optional, Callable, Dict
import logging

from env_config import load_project_env_once

load_project_env_once()

logger = logging.getLogger('SmartCarSensors')

# ============================================================
# Sensor Data
# ============================================================

@dataclass
class ObstacleData:
    distance: float       # meters
    angle: float          # degrees (-90 to 90)
    velocity: float       # m/s (relative)
    type: str             # "vehicle", "pedestrian", "static", "none"
    confidence: float     # 0-1

@dataclass
class GPSData:
    latitude: float
    longitude: float
    altitude: float
    speed_kmh: float
    heading: float        # degrees (0-360)
    accuracy: float       # meters
    satellites: int

@dataclass
class EngineData:
    rpm: float
    temperature: float    # Â°C
    oil_pressure: float   # bar
    coolant_temp: float   # Â°C
    throttle_pos: float   # %
    fuel_level: float     # %
    battery_voltage: float  # V

@dataclass
class BrakeData:
    pressure: float       # % (0-100)
    abs_active: bool
    traction_control: bool
    emergency_brake: bool


@dataclass
class BiometricData:
    heart_rate_bpm: float
    drowsiness_score: float
    unwell: bool

# ============================================================
# Obstacle Sensor (LIDAR/Radar Simulation)
# ============================================================

class ObstacleSensor:
    """Simulates front-facing radar/LIDAR with 100m emergency zone"""
    EMERGENCY_DISTANCE = 100.0

    def __init__(self):
        self._obstacles: list = []
        self._noise_level = 0.02  # 2% noise
        self._lock = threading.Lock()
        self._running = False
        self._callbacks: list = []
        self._min_distance = 999.0

    def add_obstacle(self, distance: float, angle: float = 0.0,
                     velocity: float = 0.0, type_: str = "vehicle"):
        with self._lock:
            self._obstacles.append(ObstacleData(
                distance=distance, angle=angle, velocity=velocity,
                type=type_, confidence=0.95
            ))

    def clear_obstacles(self):
        with self._lock:
            self._obstacles.clear()

    def remove_closest(self):
        with self._lock:
            if self._obstacles:
                self._obstacles.pop(0)

    def on_emergency(self, callback: Callable):
        self._callbacks.append(callback)

    def scan(self) -> Optional[ObstacleData]:
        """Return closest obstacle within range"""
        with self._lock:
            if not self._obstacles:
                self._min_distance = 999.0
                return None
            # Add sensor noise
            sorted_obs = sorted(self._obstacles, key=lambda o: o.distance)
            closest = sorted_obs[0]
            noisy_dist = closest.distance * (1 + random.gauss(0, self._noise_level))
            result = ObstacleData(
                distance=max(0.5, noisy_dist),
                angle=closest.angle,
                velocity=closest.velocity,
                type=closest.type,
                confidence=closest.confidence
            )
            self._min_distance = result.distance
            if result.distance < self.EMERGENCY_DISTANCE:
                for cb in self._callbacks:
                    cb(result)
            return result

    def get_min_distance(self) -> float:
        return self._min_distance

    def start_simulation(self, scenario: str = "clear"):
        """Start a driving scenario simulation"""
        self._running = True
        scenarios = {
            "clear": self._scenario_clear,
            "city": self._scenario_city,
            "highway": self._scenario_highway,
            "emergency": self._scenario_emergency,
        }
        fn = scenarios.get(scenario, self._scenario_clear)
        t = threading.Thread(target=fn, daemon=True)
        t.start()

    def _scenario_clear(self):
        self.clear_obstacles()
        while self._running:
            time.sleep(0.5)

    def _scenario_city(self):
        """City driving - frequent stops and pedestrians"""
        while self._running:
            # Random pedestrian appears
            if random.random() < 0.1:
                self.add_obstacle(random.uniform(30, 80), random.uniform(-15,15),
                                  random.uniform(-2, 2), "pedestrian")
            time.sleep(random.uniform(2, 5))
            self.clear_obstacles()

    def _scenario_highway(self):
        """Highway - fast vehicles"""
        while self._running:
            dist = random.uniform(50, 200)
            self.add_obstacle(dist, 0, random.uniform(-5, 5), "vehicle")
            # Obstacle approaches
            for _ in range(20):
                if not self._running: break
                with self._lock:
                    if self._obstacles:
                        self._obstacles[0].distance -= 2
                time.sleep(0.3)
            self.clear_obstacles()
            time.sleep(2)

    def _scenario_emergency(self):
        """Emergency: sudden obstacle appears within 100m"""
        time.sleep(3)
        self.add_obstacle(55.0, 0, -10, "vehicle")  # Emergency!
        time.sleep(5)
        self.clear_obstacles()


# ============================================================
# GPS Simulation
# ============================================================

class GPSSimulator:
    def __init__(self, start_lat: float = 23.8103, start_lon: float = 90.4125):
        self.lat = start_lat
        self.lon = start_lon
        self.altitude = 8.0  # meters above sea level (Dhaka ~8m)
        self.heading = 0.0
        self.speed_kmh = 0.0

    def update(self, speed_kmh: float, heading_change: float = 0):
        self.speed_kmh = speed_kmh
        self.heading = (self.heading + heading_change) % 360
        # Calculate position delta
        speed_ms = speed_kmh / 3.6
        dt = 0.1  # 100ms
        d = speed_ms * dt / 111_111  # degrees per meter
        self.lat += d * math.cos(math.radians(self.heading))
        self.lon += d * math.sin(math.radians(self.heading))
        # Add GPS noise
        noise = 0.00001
        self.lat += random.gauss(0, noise)
        self.lon += random.gauss(0, noise)

    def get(self) -> GPSData:
        return GPSData(
            latitude=self.lat,
            longitude=self.lon,
            altitude=self.altitude + random.gauss(0, 0.5),
            speed_kmh=self.speed_kmh,
            heading=self.heading,
            accuracy=random.uniform(1.5, 4.0),
            satellites=random.randint(8, 12)
        )


# ============================================================
# Engine Simulator
# ============================================================

class EngineSimulator:
    def __init__(self):
        self.running = False
        self.rpm = 0.0
        self.temperature = 20.0
        self.oil_pressure = 0.0
        self.coolant_temp = 20.0
        self.throttle = 0.0
        self.fuel_level = 100.0
        self.battery_voltage = 12.6

    def start(self):
        self.running = True
        self.rpm = 800  # idle RPM
        self.oil_pressure = 3.5

    def stop(self):
        self.running = False
        self.rpm = 0
        self.oil_pressure = 0

    def update(self, throttle: float, dt: float = 0.1):
        if not self.running:
            return
        self.throttle = max(0, min(100, throttle))
        target_rpm = 800 + (throttle / 100) * 6200
        self.rpm += (target_rpm - self.rpm) * 0.1
        # Temperature
        if self.temperature < 90:
            self.temperature += 0.05 * dt
        else:
            self.temperature = 90 + random.gauss(0, 0.5)
        # Fuel consumption
        self.fuel_level -= (0.00001 + throttle * 0.000005) * dt
        self.fuel_level = max(0, self.fuel_level)
        # Battery
        self.battery_voltage = 13.8 + random.gauss(0, 0.05)
        self.coolant_temp = self.temperature - random.uniform(2, 5)
        self.oil_pressure = 3.5 + (self.rpm / 6000) * 1.5 + random.gauss(0, 0.1)

    def get(self) -> EngineData:
        return EngineData(
            rpm=self.rpm,
            temperature=self.temperature,
            oil_pressure=self.oil_pressure,
            coolant_temp=self.coolant_temp,
            throttle_pos=self.throttle,
            fuel_level=self.fuel_level,
            battery_voltage=self.battery_voltage
        )


# ============================================================
# Emergency Brake Controller
# ============================================================

class EmergencyBrakeController:
    """
    Monitors obstacle distance and triggers emergency brake
    when obstacle is within 100 meters
    """
    EMERGENCY_DISTANCE = 100.0
    WARNING_DISTANCE = 150.0
    CRITICAL_DISTANCE = 30.0

    def __init__(self, obstacle_sensor: ObstacleSensor):
        self.sensor = obstacle_sensor
        self.brake_active = False
        self.brake_pressure = 0.0
        self._callbacks: list = []
        self.sensor.on_emergency(self._on_obstacle_detected)

    def on_brake_event(self, callback: Callable):
        self._callbacks.append(callback)

    def _on_obstacle_detected(self, obstacle: ObstacleData):
        if obstacle.distance < self.EMERGENCY_DISTANCE:
            self.brake_active = True
            # Proportional braking based on distance
            if obstacle.distance < self.CRITICAL_DISTANCE:
                self.brake_pressure = 100.0
            else:
                self.brake_pressure = (1 - obstacle.distance / self.EMERGENCY_DISTANCE) * 100
            for cb in self._callbacks:
                cb(obstacle, self.brake_pressure)
            logger.warning(f"EMERGENCY BRAKE: obstacle at {obstacle.distance:.1f}m, "
                          f"brake pressure: {self.brake_pressure:.1f}%")

    def release_brake(self):
        self.brake_active = False
        self.brake_pressure = 0.0

    def get_status(self) -> BrakeData:
        return BrakeData(
            pressure=self.brake_pressure,
            abs_active=self.brake_active and self.brake_pressure > 80,
            traction_control=True,
            emergency_brake=self.brake_active
        )


# ============================================================
# Complete Vehicle Sensor Suite
# ============================================================

class VehicleSensorSuite:
    def __init__(self, start_lat: float = 23.8103, start_lon: float = 90.4125):
        self.obstacle = ObstacleSensor()
        self.gps = GPSSimulator(start_lat, start_lon)
        self.engine = EngineSimulator()
        self.brake = EmergencyBrakeController(self.obstacle)
        self._speed = 0.0
        self._throttle = 0.0
        self._biometric_provider: Optional[Callable[[], Dict]] = None
        self._last_biometric = BiometricData(heart_rate_bpm=72.0, drowsiness_score=0.0, unwell=False)

    def set_biometric_provider(self, provider: Callable[[], Dict]):
        """
        Register real biometric provider.
        provider() should return dict with:
          heart_rate_bpm, drowsiness_score, unwell
        """
        self._biometric_provider = provider

    def _read_biometric(self) -> BiometricData:
        if not self._biometric_provider:
            return self._last_biometric
        try:
            raw = self._biometric_provider() or {}
            hr = float(raw.get("heart_rate_bpm", self._last_biometric.heart_rate_bpm))
            drowsy = float(raw.get("drowsiness_score", self._last_biometric.drowsiness_score))
            unwell = bool(raw.get("unwell", False))
            self._last_biometric = BiometricData(
                heart_rate_bpm=max(20.0, min(240.0, hr)),
                drowsiness_score=max(0.0, min(1.0, drowsy)),
                unwell=unwell,
            )
        except Exception:
            pass
        return self._last_biometric

    def update(self, speed: float = None, throttle: float = None, heading_change: float = 0):
        if speed is not None:
            self._speed = speed
        if throttle is not None:
            self._throttle = throttle
        self.gps.update(self._speed, heading_change)
        self.engine.update(self._throttle)

    def full_scan(self) -> dict:
        obstacle = self.obstacle.scan()
        gps = self.gps.get()
        engine = self.engine.get()
        brake_status = self.brake.get_status()
        bio = self._read_biometric()
        return {
            'obstacle': {
                'distance': obstacle.distance if obstacle else 999.0,
                'type': obstacle.type if obstacle else 'none',
                'angle': obstacle.angle if obstacle else 0.0,
            } if obstacle else {'distance': 999.0, 'type': 'none', 'angle': 0.0},
            'gps': {
                'lat': gps.latitude, 'lon': gps.longitude,
                'speed_kmh': gps.speed_kmh, 'heading': gps.heading,
                'accuracy': gps.accuracy, 'satellites': gps.satellites,
            },
            'engine': {
                'rpm': engine.rpm, 'temperature': engine.temperature,
                'fuel_level': engine.fuel_level,
                'battery_voltage': engine.battery_voltage,
                'throttle': engine.throttle_pos,
            },
            'brake': {
                'pressure': brake_status.pressure,
                'emergency': brake_status.emergency_brake,
                'abs': brake_status.abs_active,
            },
            'biometric': {
                'heart_rate_bpm': bio.heart_rate_bpm,
                'drowsiness_score': bio.drowsiness_score,
                'unwell': bio.unwell,
            }
        }


if __name__ == "__main__":
    print("Sensor Suite Test")
    suite = VehicleSensorSuite()
    suite.engine.start()
    suite.obstacle.add_obstacle(45.0, 0, -5, "vehicle")

    def on_brake(obs, pressure):
        print(f"ðŸš¨ EMERGENCY BRAKE! Obstacle: {obs.distance:.1f}m, Pressure: {pressure:.1f}%")

    suite.brake.on_brake_event(on_brake)

    for i in range(5):
        suite.update(speed=80, throttle=50)
        data = suite.full_scan()
        print(f"Scan {i+1}: obstacle={data['obstacle']['distance']:.1f}m, "
              f"speed={data['gps']['speed_kmh']:.1f}km/h, "
              f"rpm={data['engine']['rpm']:.0f}")
        time.sleep(0.5)

    print("Sensor test complete.")
