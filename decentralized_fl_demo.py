# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Decentralized federated-learning demo over blockchain events.

Each car trains locally from obstacle telemetry, shares only model weights delta,
and peer cars aggregate those deltas without sharing raw data.
"""

from blockchain import SmartCarBlockchain, TelemetryData
from federated_learning import print_prototype_fl_sanity_check


def _mk_car(cid: str) -> SmartCarBlockchain:
    bc = SmartCarBlockchain(
        vehicle_id=cid,
        password="demo_pass",
        auth_token="demo_token",
        chain_file=f"logs/blockchain_{cid}_fl_demo.json",
    )
    bc.authenticate("demo_token")
    bc.start_engine()
    return bc


def _push_local_obstacle_data(bc: SmartCarBlockchain):
    for i in range(16):
        # Mix normal + risky obstacle situations to force local model updates.
        obstacle = 18.0 if i % 4 == 0 else 75.0
        emergency = obstacle <= 25.0
        tel = TelemetryData(
            speed=55.0 + (i % 6) * 4.0,
            obstacle_distance=obstacle,
            emergency_brake_active=emergency,
            timestamp=bc._now(),
        )
        event = "OBSTACLE:NEW_PATTERN" if emergency else "TELEMETRY:NORMAL"
        bc.push_telemetry(tel, event)


def _collect_fl_updates(source: SmartCarBlockchain):
    return source.get_fl_update_payloads(since_block_index=0)


def main():
    car_a = _mk_car("CAR_A_FL")
    car_b = _mk_car("CAR_B_FL")
    car_c = _mk_car("CAR_C_FL")

    _push_local_obstacle_data(car_a)
    updates_from_a = _collect_fl_updates(car_a)

    applied_b = 0
    applied_c = 0
    for up in updates_from_a:
        if car_b.apply_remote_fl_update(up).get("applied"):
            applied_b += 1
        if car_c.apply_remote_fl_update(up).get("applied"):
            applied_c += 1

    print_prototype_fl_sanity_check(num_peers=3, test_samples=24)
    print("=== Decentralized FL Demo ===")
    print(f"car_a_updates_shared={len(updates_from_a)}")
    print(f"car_b_updates_applied={applied_b}")
    print(f"car_c_updates_applied={applied_c}")
    print(f"car_a_model={car_a.get_fl_model_snapshot()}")
    print(f"car_b_model={car_b.get_fl_model_snapshot()}")
    print(f"car_c_model={car_c.get_fl_model_snapshot()}")


if __name__ == "__main__":
    main()
