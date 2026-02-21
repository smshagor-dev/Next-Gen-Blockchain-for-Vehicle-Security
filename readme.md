# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer

SmartCar research platform with blockchain audit trail, PoA consensus, ZKP-based privacy checks, V2X communication, DID, edge processing, anomaly detection, and hardware bridge support.

## Project Layers

1. `Presentation Layer`
- `main.py`, `dashboard.py`
- Live telemetry UI, camera/object detection view, road SVG, speedometer, chain/event panels

2. `Application Layer`
- `blockchain.py`, `smart_contracts.py`, `edge_layer.py`, `anomaly_detector.py`, `did_identity.py`
- Core security logic, smart-contract orchestration, edge summarization, anomaly scoring, DID verification

3. `Network Layer`
- `sync_protocol.py`, `v2x_protocol.py`, `multi_car_majority_demo.py`, `v2x_demo_nodes.py`
- Multi-node sync, majority vote, V2V/V2I exchange, telemetry relay

4. `Privacy/Crypto Layer`
- `zkp_privacy.py`
- Commitment-based lightweight ZKP proofs for speed-limit and location-ownership validation

5. `Hardware/Edge Integration Layer`
- `hardware_bridge.py`, `pi_sensor_node.py`, `SmartCarSensorNode.ino`, `camera_emergency_brake.cpp`
- Arduino/Raspberry Pi input bridge and C++ camera emergency braking pipeline

6. `Observability Layer`
- `perf_metrics.py`, `zkp_latency_report.py`, `network_overhead_analysis.py`, `logs/`
- ZKP latency metrics, network overhead reports/charts, runtime logs

## Root Structure (Current)

```text
Smart Car/
|- main.py
|- dashboard.py
|- blockchain.py
|- sync_protocol.py
|- v2x_protocol.py
|- zkp_privacy.py
|- did_identity.py
|- smart_contracts.py
|- edge_layer.py
|- anomaly_detector.py
|- env_config.py
|- hardware_bridge.py
|- pi_sensor_node.py
|- SmartCarSensorNode.ino
|- camera_emergency_brake.cpp
|- multi_car_majority_demo.py
|- attacker_fake_zkp.py
|- network_overhead_analysis.py
|- perf_metrics.py
|- zkp_latency_report.py
|- .env
|- logs/
|- image source/
```

## Production-Oriented ZKP Parameters

`zkp_privacy.py` now supports dynamic parameter loading:

- `SMARTCAR_ZKP_PARAM_SET=RFC3526_GROUP14` (default, standard 2048-bit MODP group)
- `SMARTCAR_ZKP_PARAM_SET=MERSENNE_521` (legacy lightweight mode)
- Optional custom override:
  - `SMARTCAR_ZKP_P`
  - `SMARTCAR_ZKP_G`
  - `SMARTCAR_ZKP_H`

All values are read from `.env` at runtime.

## Network Error Handling Hardening

`sync_protocol.py` and `v2x_protocol.py` now include stronger socket exception handling:

- timeout retry flow for receive loops
- explicit handling for disconnect/reset conditions (`BrokenPipeError`, `ConnectionResetError`, `ConnectionAbortedError`)
- guarded send helpers and safer shutdown/cleanup paths

## Local Storage Encryption (Blockchain File)

`blockchain.py` now supports encryption-at-rest for the saved chain file (`logs/blockchain_*.json`):

- Primary mode: `AES-256-GCM` (when `cryptography` is available)
- Fallback mode: authenticated encrypted envelope (`PBKDF2-SHA256-STREAM-HMAC`)

Config in `.env`:

- `SMARTCAR_STORAGE_ENCRYPTION=1`
- `SMARTCAR_STORAGE_PASSPHRASE=` (optional, defaults to `SMARTCAR_PASSWORD`)
- `SMARTCAR_STORAGE_KDF_ITERATIONS=200000`

## Owner Recovery Mode

If normal auth is blocked due to lockout or chain mismatch:

- Use dashboard `RECOVER` with owner recovery key
- Optional `Force Chain Reset` can rebuild chain from fresh genesis (policy-controlled)

Config in `.env`:

- `SMARTCAR_OWNER_RECOVERY_KEY=...`
- `SMARTCAR_OWNER_ALLOW_CHAIN_RESET=1`

## Math Calculation

### 1) Block Hash

```text
block_hash = SHA3-256(index || timestamp || vehicle_id || telemetry_hash_sha3 || event_hash_sha3 || previous_hash)
```

### 2) Dual Hash

```text
sha2 = SHA2-256(block_hash)
sha3 = SHA3-256(block_hash)
dual_hash_combined = sha2 + ":" + sha3
```

### 3) PoA Block Signature (HMAC)

```text
poa_payload = block_hash + "|" + validator_id + "|" + authority_round
poa_signature = HMAC-SHA256(validator_key, poa_payload)
```

### 4) ZKP Commitment (Lightweight)

```text
C = (G^value mod P) * (H^blind mod P) mod P
```

Knowledge proof challenge:

```text
ch = H(commitment || t || context) mod (P-1)
```

Speed-limit relation check:

```text
speed + diff = limit
commit_speed * commit_diff ?= G^limit * H^(r_speed + r_diff) (mod P)
```

### 5) Camera Distance Estimation

Used in dashboard object detection:

```text
distance_m = (real_object_height_m * focal_length_px) / bbox_height_px
```

Current implementation constant form:

```text
distance_m = (1.70 * 850.0) / bbox_height_px
```

### 6) Speedometer Needle Angle

For max speed `Vmax` and current speed `v`:

```text
angle_deg = start_deg - (v / Vmax) * sweep_deg
```

Current UI values:

```text
start_deg = 162
sweep_deg = 144
Vmax = 220 km/h
```

## Docstring Update

Short docstrings were added in updated modules for maintainability:

- `zkp_privacy.py`
- `sync_protocol.py`
- `v2x_protocol.py`
- `env_config.py`

## Run

Start GUI:

```bash
python main.py
```

Optional demos:

```bash
python multi_car_majority_demo.py
python v2x_demo_nodes.py
python attacker_fake_zkp.py
python zkp_latency_report.py
python network_overhead_analysis.py
```

Camera C++ module:

```bash
g++ camera_emergency_brake.cpp -o camera_emergency_brake `pkg-config --cflags --libs opencv4`
./camera_emergency_brake
```

## Final Check (Current)

- Root-level architecture is in sync with flattened project layout
- GUI starts from `main.py` and opens in fullscreen mode
- Right panel supports mouse-wheel scrolling
- Access status block shows `LOCK`, `AUTH`, and `ENGINE (START/STOP)` live
- Dual Hash Chain panel is placed below Road Scene and Blockchain Ledger Feed
- `_update_ui` and network stack now log exceptions instead of silent pass
