# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Federated trainer node demo:
- collects local car model updates
- aggregates into global model
- trainer can also train itself on trainer-side labeled samples
- broadcasts global model back to cars (here via direct API call)
"""

from blockchain import SmartCarBlockchain, TelemetryData
from federated_learning import FederatedTrainer, print_prototype_fl_sanity_check
from env_config import load_project_env_once, get_float

load_project_env_once()


def _mk_car(cid: str) -> SmartCarBlockchain:
    bc = SmartCarBlockchain(
        vehicle_id=cid,
        password="trainer_pass",
        auth_token="trainer_token",
        chain_file=f"logs/blockchain_{cid}_trainer_demo.json",
    )
    bc.authenticate("trainer_token")
    bc.start_engine()
    bc.fl_learner.min_samples_per_update = 8
    bc.fl_update_min_interval_sec = 0.0
    return bc


def _generate_local_training(bc: SmartCarBlockchain, n: int = 10):
    for i in range(n):
        close = (i % 4 == 0)
        obstacle = 16.0 if close else 88.0
        tel = TelemetryData(
            speed=52.0 + (i % 6) * 5.0,
            acceleration=1.0 if not close else -2.8,
            brake_pressure=80.0 if close else 10.0,
            engine_temp=78.0 + (i % 5),
            obstacle_distance=obstacle,
            emergency_brake_active=close,
            driver_drowsiness_score=0.15 if not close else 0.75,
            driver_heart_rate_bpm=80.0 if not close else 112.0,
            driver_unwell=False,
            timestamp=bc._now(),
        )
        bc.push_telemetry(tel, "OBSTACLE:NEW_PATTERN" if close else "TELEMETRY:NORMAL")


def main():
    car_a = _mk_car("CAR_A_RT")
    car_b = _mk_car("CAR_B_RT")
    car_c = _mk_car("CAR_C_RT")

    _generate_local_training(car_a)
    _generate_local_training(car_b)
    _generate_local_training(car_c)

    updates = []
    updates.extend(car_a.get_fl_update_payloads())
    updates.extend(car_b.get_fl_update_payloads())
    updates.extend(car_c.get_fl_update_payloads())

    trainer = FederatedTrainer(trainer_id="TRAINER_DC_01")
    trainer.outlier_mad_k = get_float("SMARTCAR_FL_TRAINER_OUTLIER_MAD_K", 3.5)
    trainer.trim_ratio = get_float("SMARTCAR_FL_TRAINER_TRIM_RATIO", 0.20)
    trainer.max_client_delta_norm = get_float("SMARTCAR_FL_TRAINER_MAX_CLIENT_DELTA_NORM", 0.85)
    agg = trainer.aggregate_updates(updates)
    if not agg.get("ok"):
        print("No valid updates to aggregate.")
        return

    trainer_samples = [
        {"telemetry": {"speed": 70, "obstacle_distance": 20, "brake_pressure": 75, "acceleration": -3.2}, "label_risk": True},
        {"telemetry": {"speed": 62, "obstacle_distance": 95, "brake_pressure": 5, "acceleration": 1.0}, "label_risk": False},
        {"telemetry": {"speed": 84, "obstacle_distance": 26, "brake_pressure": 68, "acceleration": -2.1}, "label_risk": True},
        {"telemetry": {"speed": 55, "obstacle_distance": 110, "brake_pressure": 8, "acceleration": 0.6}, "label_risk": False},
    ]
    trainer_train = trainer.train_trainer(trainer_samples, epochs=3)
    global_model = trainer.export_global_model()

    print_prototype_fl_sanity_check(num_peers=3, test_samples=24)
    print("=== Trainer Node Demo ===")
    print(f"aggregated_updates={agg.get('updates_count')}")
    print(f"global_round_after_aggregate={agg.get('global_round')}")
    print(f"trainer_self_train_ok={trainer_train.get('ok')}")
    print(f"global_model_round={global_model.get('global_round')}")

    print("\n=== Apply Global Model to Cars ===")
    print("car_a", car_a.apply_global_fl_model(global_model).get("applied"))
    print("car_b", car_b.apply_global_fl_model(global_model).get("applied"))
    print("car_c", car_c.apply_global_fl_model(global_model).get("applied"))
    print("car_a_model", car_a.get_fl_model_snapshot())
    print("car_b_model", car_b.get_fl_model_snapshot())
    print("car_c_model", car_c.get_fl_model_snapshot())


if __name__ == "__main__":
    main()
