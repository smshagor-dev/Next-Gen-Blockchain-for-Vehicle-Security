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

## Quantum-Resistant V2V Handshake (Dynamic PQC)

`v2x_protocol.py` now includes a dynamic cryptographic agility layer:

- handshake exchanges crypto capability (`SHA3`, `DILITHIUM`)
- each node monitors latency/traffic and auto-switches mode
- high latency / high traffic -> lightweight `SHA3` envelope
- normal conditions / quantum-alert mode -> `DILITHIUM` path
- handshake now attempts PQ KEM (`ML-KEM-512` / `Kyber512`) to derive a per-session secret
- if `oqs`/PQC path is unavailable, it automatically falls back to classical `ECDH + HKDF` key exchange and `ECDSA` signatures
- agility switching now uses EWMA-smoothed latency + traffic score with hysteresis (`up/down` thresholds)
- mode switching requires consecutive confirmation decisions to reduce crypto-mode flapping under noisy links

This keeps real-time decision latency stable while still enabling quantum-resistant mode when possible.

Config in `.env`:

- `SMARTCAR_V2X_SHARED_SECRET=...`
- `SMARTCAR_V2X_CRYPTO_DEFAULT=DILITHIUM`
- `SMARTCAR_V2X_CRYPTO_FORCE_MODE=`
- `SMARTCAR_V2X_CRYPTO_SWITCH_INTERVAL_SEC=2.0`
- `SMARTCAR_V2X_CRYPTO_LATENCY_HIGH_MS=120`
- `SMARTCAR_V2X_CRYPTO_TRAFFIC_HIGH_MPS=60`
- `SMARTCAR_V2X_CRYPTO_METRICS_WINDOW_SEC=4.0`
- `SMARTCAR_V2X_CRYPTO_EWMA_ALPHA=0.28`
- `SMARTCAR_V2X_CRYPTO_WEIGHT_LATENCY=0.65`
- `SMARTCAR_V2X_CRYPTO_WEIGHT_TRAFFIC=0.35`
- `SMARTCAR_V2X_CRYPTO_SCORE_UP_THRESHOLD=0.72`
- `SMARTCAR_V2X_CRYPTO_SCORE_DOWN_THRESHOLD=0.54`
- `SMARTCAR_V2X_CRYPTO_REC_BIAS=0.08`
- `SMARTCAR_V2X_CRYPTO_QUANTUM_GUARD_MAX_SCORE=0.90`
- `SMARTCAR_V2X_CRYPTO_SWITCH_CONFIRM_COUNT=2`
- `SMARTCAR_V2X_HUB_LATENCY_HINT_MS=20`
- `SMARTCAR_V2X_QUANTUM_ALERT=0`
- `SMARTCAR_V2X_FORCE_CLASSIC=0`
- `SMARTCAR_V2X_PQC_SIG_ALG=Dilithium2`
- `SMARTCAR_V2X_PQC_KEM_PREFERRED=Kyber512`
- `SMARTCAR_V2X_PQC_KEM_ALGS=ML-KEM-512,Kyber512`

## Local Storage Encryption (Blockchain File)

`blockchain.py` now supports encryption-at-rest for the saved chain file (`logs/blockchain_*.json`):

- Primary mode: `AES-256-GCM` (when `cryptography` is available)
- Fallback mode: authenticated encrypted envelope (`PBKDF2-SHA256-STREAM-HMAC`)

Config in `.env`:

- `SMARTCAR_STORAGE_ENCRYPTION=1`
- `SMARTCAR_STORAGE_PASSPHRASE=` (optional, defaults to `SMARTCAR_PASSWORD`)
- `SMARTCAR_STORAGE_KDF_ITERATIONS=200000`

## Encrypted Blackbox Logging (Forensic Analysis)

If a hacking/security-breach pattern or physical-impact/emergency event is detected, the system now:

1. keeps a rolling last `10 minutes` of raw telemetry/event samples
2. locks that raw timeline in a strong encrypted forensic package
3. writes the locked package into the triggered blockchain block
4. wraps access key material separately for:
   - forensic team
   - insurance company
5. additionally pushes a special `FORENSIC_BLOCK:*` from edge raw queue snapshot on impact

Config in `.env`:

- `SMARTCAR_BLACKBOX_WINDOW_SEC=600`
- `SMARTCAR_BLACKBOX_SAMPLE_HZ=2`
- `SMARTCAR_BLACKBOX_KDF_ITERATIONS=250000`
- `SMARTCAR_FORENSIC_ACCESS_KEY=...`
- `SMARTCAR_INSURANCE_ACCESS_KEY=...`
- `SMARTCAR_EDGE_FORENSIC_QUEUE_SIZE=2400`
- `SMARTCAR_EDGE_FORENSIC_WINDOW_SEC=600`
- `SMARTCAR_FORENSIC_BLOCK_COOLDOWN_SEC=3.0`

## Multi-Modal Biometric Auth via Blockchain

Driver biometric safety signals are now included in each telemetry block:

- `driver_heart_rate_bpm`
- `driver_drowsiness_score`
- `driver_unwell`

The blockchain stores a dedicated biometric digest:

- `biometric_hash_sha3 = SHA3-256(heart_rate | drowsiness | unwell_flag)`

If biometric risk is detected (abnormal heart rate / high drowsiness / unwell flag), a smart contract can auto-trigger vehicle safe mode.

Config in `.env`:

- `BIOMETRIC_SAFETY_CONTRACT_ENABLED=1`
- `BIOMETRIC_HEART_RATE_LOW_BPM=45`
- `BIOMETRIC_HEART_RATE_HIGH_BPM=140`
- `BIOMETRIC_DROWSINESS_THRESHOLD=0.80`

## Decentralized AI-Model Training (Federated Learning)

Cars can now train a lightweight obstacle-risk model locally and share only model `weights_delta` over blockchain.
Raw telemetry is not shared.

Flow:

1. each car ingests local obstacle telemetry
2. local learner creates periodic `FL:MODEL_UPDATE:*` block events
3. peer cars apply remote deltas via aggregation (`FL:AGGREGATE_UPDATE:*`)
4. trainer node can aggregate and also self-train (`train_trainer`) before publishing global weights

Security hardening:

- Weight poisoning defense:
  - client delta norm gate
  - trainer-side MAD outlier filter
  - robust weighted trimmed-mean aggregation
- Differential Privacy:
  - client update delta clipping
  - Gaussian noise on delta before sharing
  - raw telemetry never leaves car

Config in `.env`:

- `SMARTCAR_FL_ENABLED=1`
- `SMARTCAR_FL_UPDATE_INTERVAL_SEC=8.0`
- `SMARTCAR_FL_LEARNING_RATE=0.05`
- `SMARTCAR_FL_LOCAL_EPOCHS=3`
- `SMARTCAR_FL_MIN_SAMPLES=12`
- `SMARTCAR_FL_DP_ENABLED=1`
- `SMARTCAR_FL_DP_NOISE_SIGMA=0.010`
- `SMARTCAR_FL_DELTA_CLIP_NORM=0.25`
- `SMARTCAR_FL_REMOTE_DELTA_MAX_NORM=0.65`
- `SMARTCAR_FL_TRAINER_OUTLIER_MAD_K=3.5`
- `SMARTCAR_FL_TRAINER_TRIM_RATIO=0.20`
- `SMARTCAR_FL_TRAINER_MAX_CLIENT_DELTA_NORM=0.85`

## Self-Healing Blockchain (Pruning + Sharding)

To optimize limited in-vehicle memory, old low-priority blocks are compacted and archived:

1. old blocks are grouped into archive shards
2. shard payload is written to archive-node file
3. shard root-hash is retained on-chain metadata (`archive_root_hash`)
4. archived blocks are compacted in main chain to reduce memory footprint
5. cross-shard verification proof can be generated/verified via Merkle membership + anchored shard root
6. state checkpoint snapshot is generated and signed after prune milestones
7. storage pressure (free MB / free %) can auto-trigger aggressive pruning
8. shard sync bundle exchange allows cars to share signed shard anchors across shards/nodes

Config in `.env`:

- `SMARTCAR_PRUNING_ENABLED=1`
- `SMARTCAR_PRUNE_KEEP_RECENT_BLOCKS=200`
- `SMARTCAR_PRUNE_BATCH_SIZE=50`
- `SMARTCAR_ARCHIVE_NODE_FILE=logs/archive_node.jsonl`
- `SMARTCAR_SHARD_SYNC_ENABLED=1`
- `SMARTCAR_SHARD_SYNC_MAX_ANCHORS=1024`
- `SMARTCAR_SHARD_SYNC_BUNDLE_FILE=logs/shard_sync_bundle_smartcar.json`
- `SMARTCAR_CHECKPOINT_ENABLED=1`
- `SMARTCAR_CHECKPOINT_EVERY_N_SHARDS=1`
- `SMARTCAR_CHECKPOINT_MIN_INTERVAL_SEC=8`
- `SMARTCAR_CHECKPOINT_FILE=logs/state_checkpoint_smartcar.json`
- `SMARTCAR_CHECKPOINT_HISTORY_FILE=logs/state_checkpoint_history_smartcar.jsonl`
- `SMARTCAR_AUTO_STORAGE_MANAGEMENT_ENABLED=1`
- `SMARTCAR_STORAGE_MIN_FREE_MB=512`
- `SMARTCAR_STORAGE_MIN_FREE_PERCENT=8`
- `SMARTCAR_STORAGE_CRITICAL_FREE_MB=256`
- `SMARTCAR_STORAGE_CRITICAL_FREE_PERCENT=4`
- `SMARTCAR_STORAGE_PRUNE_BATCH_MULTIPLIER=2`
- `SMARTCAR_STORAGE_CRITICAL_PRUNE_BATCH_MULTIPLIER=4`

Sharding sync APIs (in `blockchain.py`):

- `export_shard_sync_bundle(max_anchors=128, write_file=True)`
- `import_shard_sync_bundle(bundle, strict_checkpoint=False)`
- `create_cross_shard_proof(shard_id, block_index)`
- `verify_cross_shard_proof(proof_payload)`
- `get_shard_sync_status()`

## Platooning Security with Proof-of-Proximity (PoP)

For platooning scenarios, blockchain approval can be bound to physical LIDAR proximity evidence:

1. nearby vehicles submit proximity observations (`distance_m`, `confidence`)
2. block approval requires distance-in-range + minimum participant confirmations
3. PoP proof hash is stored in block metadata (physical-digital binding)
4. if PoP fails, block is marked as `PLATOON:BLOCKED:POP_FAIL:*`

Config in `.env`:

- `SMARTCAR_PLATOON_POP_ENABLED=1`
- `SMARTCAR_POP_DISTANCE_MIN_M=5`
- `SMARTCAR_POP_DISTANCE_MAX_M=55`
- `SMARTCAR_POP_OBSERVATION_TTL_SEC=1.5`
- `SMARTCAR_POP_REQUIRED_PARTICIPANTS=2`
- `SMARTCAR_POP_MIN_CONFIDENCE=0.80`

### Real Safe-Mode Hardware Dispatch (ECU)

When biometric risk triggers safe mode, `hardware_bridge.py` now dispatches hard-stop command to ECU:

- primary path: CAN frame (extended ID)
- fallback path: serial JSON command to ECU controller

Config in `.env`:

- `SMARTCAR_ECU_CONTROL_ENABLED=1`
- `SMARTCAR_ECU_MODE=can` (or `serial`)
- `SMARTCAR_ECU_CAN_CHANNEL=can0`
- `SMARTCAR_ECU_CAN_BUSTYPE=socketcan`
- `SMARTCAR_ECU_CAN_BITRATE=500000`
- `SMARTCAR_ECU_CAN_ARB_ID=0x18FF50E5`
- `SMARTCAR_ECU_SERIAL_PORT=COM5`
- `SMARTCAR_ECU_SERIAL_BAUD=115200`

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
python pqc_kyber_handshake_test.py
python attacker_fake_zkp.py
python zkp_latency_report.py
python network_overhead_analysis.py
python decentralized_fl_demo.py
python fl_trainer_node.py
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
