# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Run demo V2X nodes (one external vehicle + one traffic signal).
Use with dashboard (python main.py) to generate live V2V/V2I blockchain events.
"""

import time
import math
import random
import os

from env_config import load_project_env_once
load_project_env_once()

from v2x_protocol import V2XNode
from zkp_privacy import create_speed_limit_proof


def main():
    host = os.getenv("SMARTCAR_V2X_HOST", "127.0.0.1")
    port = int(os.getenv("SMARTCAR_V2X_PORT", "9988"))

    car = V2XNode("peer_vehicle_01", "vehicle", host=host, port=port)
    infra = V2XNode("infra_signal_ext", "infrastructure", host=host, port=port)

    if not car.connect():
        print("peer_vehicle_01 connect failed")
        return
    if not infra.connect():
        print("infra_signal_ext connect failed")
        car.disconnect()
        return

    print(f"Connected demo nodes to {host}:{port}")
    print("Press Ctrl+C to stop")

    t = 0.0
    signal_states = ["GREEN", "YELLOW", "RED", "GREEN"]
    speed_map = {"GREEN": 80, "YELLOW": 50, "RED": 20}
    sidx = 0
    last_signal = 0.0
    base_lat = 23.8108
    base_lon = 90.4121

    try:
        while True:
            speed = 50.0 + 20.0 * math.sin(t)
            lat = base_lat + 0.0002 * math.sin(t / 3.0) + random.uniform(-0.00001, 0.00001)
            lon = base_lon + 0.0002 * math.cos(t / 3.0) + random.uniform(-0.00001, 0.00001)
            car.send_v2v_telemetry(speed=speed, lat=lat, lon=lon, heading=0.0)

            now = time.time()
            if now - last_signal >= 8.0:
                state = signal_states[sidx % len(signal_states)]
                speed_limit = speed_map.get(state, 60)
                dist_to_signal = 55
                ctx = f"{infra.node_id}|INT_EXT_09|{state}|{speed_limit}|8|{dist_to_signal}"
                proof = create_speed_limit_proof(float(speed_limit), 120, ctx)
                infra.send_v2i_signal(
                    "INT_EXT_09",
                    state,
                    ttl_sec=8,
                    extra_payload={
                        "speed_limit_kmh": speed_limit,
                        "distance_to_signal_m": dist_to_signal,
                        "zkp_speed_limit": proof
                    }
                )
                sidx += 1
                last_signal = now

            t += 0.25
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        car.disconnect()
        infra.disconnect()


if __name__ == "__main__":
    main()

