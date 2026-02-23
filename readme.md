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

## Folder Structure (Current)

```text
Smart Car - Blockchain for Vehicle Security/
|-- main.py
|-- dashboard.py
|-- blockchain.py
|-- blockchain.cpp
|-- blockchain.h
|-- sync_protocol.py
|-- v2x_protocol.py
|-- zkp_privacy.py
|-- did_identity.py
|-- smart_contracts.py
|-- edge_layer.py
|-- anomaly_detector.py
|-- federated_learning.py
|-- fl_trainer_node.py
|-- vehicle_sensors.py
|-- hardware_bridge.py
|-- pi_sensor_node.py
|-- decentralized_fl_demo.py
|-- network_overhead_analysis.py
|-- multi_car_majority_demo.py
|-- v2x_demo_nodes.py
|-- attacker_fake_zkp.py
|-- perf_metrics.py
|-- zkp_latency_report.py
|-- pqc_kyber_handshake_test.py
|-- SmartCarSensorNode.ino
|-- camera_emergency_brake.cpp
|-- CMakeLists.txt
|-- requirements.txt
|-- .env
|-- readme.md
|-- logs/
|-- build/
|-- image_source/
|   |-- System-Architechture.png
|   |-- privacy-security-flow.png
|   |-- commonication-blockchain-synctrization.png
|   |-- federaated-learning-flow.png
|   |-- Zero-Knowladge-proofs.png
|   |-- Large-language-model.png
|   |-- project_theam.jpg
|   `-- road_scene.svg
`-- __pycache__/
```

## Image Preview (`image_source/`)

![Project Theme](image_source/project_theam.jpg)
![System Architecture](image_source/System-Architechture.png)
![Privacy Security Flow](image_source/privacy-security-flow.png)
![Blockchain Communication Sync](image_source/commonication-blockchain-synctrization.png)
![Federated Learning Flow](image_source/federaated-learning-flow.png)
![Zero Knowledge Proofs](image_source/Zero-Knowladge-proofs.png)
![Large Language Model](image_source/Large-language-model.png)

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

## Function-wise Math Calculation + Mermaid

### `blockchain.py`

#### `dual_hash(data)`

```text
sha2 = SHA2-256(data)
sha3 = SHA3-256(data)
combined = SHA2-256(data + sha3)
```

```mermaid
flowchart TD
    A[data] --> B[sha2_256]
    A --> C[sha3_256]
    A --> D[concat data+sha3]
    D --> E[sha2_256 chained]
```

#### `compute_block_hash(...)`

```text
raw = index || timestamp || vehicle_id || telemetry_hash_sha3 || event_hash_sha3 || previous_hash
block_hash = SHA3-256(raw)
```

```mermaid
flowchart TD
    A[index/timestamp/vehicle/telemetry/event/prev] --> B[concatenate]
    B --> C[SHA3-256]
    C --> D[block_hash]
```

#### `poa_sign_block(...)`

```text
payload = block_hash || "|" || validator_id || "|" || authority_round
poa_signature = HMAC-SHA256(validator_key, payload)
```

```mermaid
flowchart TD
    A[block_hash + validator + round] --> B[payload string]
    B --> C[HMAC-SHA256]
    C --> D[poa_signature]
```

#### `Block.compute_hashes(...)`

```text
telemetry_hash_sha2 = SHA2-256(telemetry_string)
telemetry_hash_sha3 = SHA3-256(telemetry_string)
event_hash_sha2 = SHA2-256(event_data)
event_hash_sha3 = SHA3-256(event_data)
dual_hash_combined = SHA2-256(block_hash) || ":" || SHA3-256(block_hash)
biometric_hash_sha3 = SHA3-256(heart_rate|drowsiness|unwell_flag)
```

```mermaid
flowchart TD
    A[telemetry,event] --> B[SHA2/SHA3 hashes]
    B --> C[compute_block_hash]
    C --> D[dual hash]
    A --> E[biometric raw string]
    E --> F[SHA3 biometric hash]
```

#### `SmartCarCrypto.encrypt(plaintext)`

```text
key = PBKDF2-HMAC-SHA256(password, salt, 100000, 64 bytes)
ciphertext = plaintext XOR keystream
mac = HMAC-SHA256(mac_key, nonce || ciphertext)
package = base64(nonce || mac || ciphertext)
```

```mermaid
flowchart TD
    A[plaintext] --> B[keystream generate]
    B --> C[XOR encrypt]
    C --> D[HMAC nonce+ciphertext]
    D --> E[base64 package]
```

#### `SmartCarCrypto.decrypt(encrypted_b64)`

```text
expected_mac = HMAC-SHA256(mac_key, nonce || ciphertext)
if mac != expected_mac => reject
plaintext = ciphertext XOR keystream
```

```mermaid
flowchart TD
    A[package] --> B[decode nonce/mac/ciphertext]
    B --> C[recompute HMAC]
    C --> D{match?}
    D -- no --> E[reject]
    D -- yes --> F[XOR decrypt]
```

### `zkp_privacy.py`

#### `commit(value, blind)`

```text
C = (G^(value mod Q) * H^r) mod P
```

```mermaid
flowchart TD
    A[value,r] --> B[pow G^value, H^r]
    B --> C[multiply mod P]
    C --> D[commitment C]
```

#### `prove_knowledge(...)`

```text
t  = (G^k1 * H^k2) mod P
ch = H(commitment|t|context) mod Q
s1 = (k1 + ch*value) mod Q
s2 = (k2 + ch*blind) mod Q
```

```mermaid
flowchart TD
    A[k1,k2] --> B[t]
    B --> C[ch]
    C --> D[s1,s2]
    D --> E[proof]
```

#### `verify_knowledge(...)`

```text
lhs = (G^s1 * H^s2) mod P
rhs = (t * commitment^ch) mod P
valid = (lhs == rhs)
```

```mermaid
flowchart TD
    A[proof + commitment] --> B[ch]
    B --> C[lhs]
    B --> D[rhs]
    C --> E{lhs==rhs}
    D --> E
```

#### `create_speed_limit_proof(...)`

```text
speed = round(speed_kmh), speed >= 0
diff = limit - speed
relation_blind = (r_speed + r_diff) mod Q
```

```mermaid
flowchart TD
    A[speed,limit] --> B[diff=limit-speed]
    B --> C[commit speed]
    B --> D[commit diff]
    C --> E[proof_speed]
    D --> F[proof_diff]
    C --> G[relation_blind]
    D --> G
```

#### `verify_speed_limit_proof(...)`

```text
lhs = (commit_speed * commit_diff) mod P
rhs = (G^limit * H^relation_blind) mod P
valid = proof_speed_ok AND proof_diff_ok AND (lhs == rhs)
```

```mermaid
flowchart TD
    A[proof object] --> B[verify speed proof]
    A --> C[verify diff proof]
    A --> D[relation check lhs==rhs]
    B --> E{all true?}
    C --> E
    D --> E
```

### `anomaly_detector.py`

#### `_mean_std(key)`

```text
mean = sum(vals)/n
var  = sum((v-mean)^2)/(n-1)
std  = sqrt(var)
```

```mermaid
flowchart TD
    A[history values] --> B[mean]
    B --> C[variance]
    C --> D[std]
```

#### `detect_telemetry(telemetry)`

```text
z = |(x-mean)/std|
zsum = z_speed + z_accel + z_temp + z_rpm
score += zsum/4 + rule_based_penalties
is_anomaly = (score >= threshold) OR (reason_count >= 2)
```

```mermaid
flowchart TD
    A[input telemetry] --> B[hard-rule penalties]
    A --> C[z-score features]
    B --> D[score]
    C --> D
    D --> E{score>=thr or reasons>=2}
```

### `edge_layer.py`

#### `_avg(vals)`

```text
avg = sum(vals)/len(vals)
```

```mermaid
flowchart TD
    A[list] --> B[sum]
    A --> C[count]
    B --> D[divide]
    C --> D
```

#### `_flush(event_hint)`

```text
speed      = avg(speed_vals)
obstacle   = min(obs_vals)
brake      = max(brake_vals)
drowsiness = max(drowsy_vals)
```

```mermaid
flowchart TD
    A[buffer telemetry] --> B[extract vectors]
    B --> C[avg metrics]
    B --> D[min metrics]
    B --> E[max metrics]
    C --> F[summary telemetry/meta]
    D --> F
    E --> F
```

### `vehicle_sensors.py`

#### `GPSSimulator.update(speed_kmh, heading_change)`

```text
speed_ms = speed_kmh / 3.6
d = speed_ms * dt / 111111
lat += d * cos(heading_rad)
lon += d * sin(heading_rad)
```

```mermaid
flowchart TD
    A[speed,heading] --> B[km/h to m/s]
    B --> C[distance in degrees]
    C --> D[update lat with cos]
    C --> E[update lon with sin]
```

#### `EngineSimulator.update(throttle, dt)`

```text
target_rpm = 800 + (throttle/100)*6200
rpm += (target_rpm - rpm)*0.1
fuel -= (0.00001 + throttle*0.000005)*dt
oil_pressure = 3.5 + (rpm/6000)*1.5 + noise
```

```mermaid
flowchart TD
    A[throttle,dt] --> B[target rpm]
    B --> C[rpm smoothing]
    A --> D[fuel decrement]
    C --> E[oil pressure]
```

#### `EmergencyBrakeController._on_obstacle_detected(obstacle)`

```text
if distance < 30m: brake_pressure = 100
else brake_pressure = (1 - distance/100)*100
```

```mermaid
flowchart TD
    A[obstacle distance] --> B{distance<100?}
    B -- no --> C[no emergency brake]
    B -- yes --> D{distance<30?}
    D -- yes --> E[pressure=100]
    D -- no --> F[pressure=(1-d/100)*100]
```

### `dashboard.py`

#### `_estimate_distance(box_h)`

```text
distance_m = (1.70 * 850.0) / box_h
```

```mermaid
flowchart TD
    A[box height] --> B[distance formula]
    B --> C[estimated meters]
```

#### `_draw_speedometer()`

```text
angle_deg = 162 - (speed/220)*144
needle_x = cx + (r-30)*cos(angle)
needle_y = cy - (r-30)*sin(angle)
```

```mermaid
flowchart TD
    A[current speed] --> B[clamp 0..220]
    B --> C[compute angle]
    C --> D[cos/sin]
    D --> E[needle position]
```

### `federated_learning.py`

#### `_sigmoid(x)`

```text
sigmoid(x) = 1 / (1 + exp(-clip(x,-40,40)))
```

```mermaid
flowchart TD
    A[x] --> B[clip]
    B --> C[exp]
    C --> D[sigmoid]
```

#### `FederatedObstacleLearner._extract_features(telemetry)`

```text
speed_norm = clip(speed/180, 0, 1)
accel_norm = clip(|accel|/12, 0, 1)
brake_norm = clip(brake/100, 0, 1)
temp_norm  = clip((temp-60)/60, 0, 1)
near_obstacle = 1 if distance<=35 else 0
hr_risk = 1 if hr<=45 or hr>=140 else 0
```

```mermaid
flowchart TD
    A[telemetry] --> B[normalize speed/accel/brake/temp]
    A --> C[threshold features]
    B --> D[feature vector]
    C --> D
```

#### `FederatedObstacleLearner._train_batch(x,y,epochs)`

```text
logits = Xw
pred = sigmoid(logits)
grad = X^T(pred - y)/n
w = w - lr*grad
loss = -mean(y*log(pred)+(1-y)*log(1-pred))
```

```mermaid
flowchart TD
    A[X,y,w] --> B[forward pass]
    B --> C[gradient]
    C --> D[weight update]
    D --> E[loss compute]
```

#### `FederatedObstacleLearner._clip_delta(delta, clip_norm)`

```text
n = ||delta||2
if n > c: delta = delta * (c/n)
```

```mermaid
flowchart TD
    A[delta] --> B[norm]
    B --> C{n>clip?}
    C -- yes --> D[scale c/n]
    C -- no --> E[keep delta]
```

#### `FederatedTrainer._mad_filter(vals,k)`

```text
med = median(vals)
mad = median(|vals - med|) + 1e-9
z = |vals - med| / mad
keep = z <= k
```

```mermaid
flowchart TD
    A[norm values] --> B[median]
    B --> C[MAD]
    C --> D[robust z]
    D --> E[keep mask]
```

#### `FederatedTrainer._robust_weighted_trimmed_mean(...)`

```text
sort each feature column
trim lowest/highest ratio
output_j = sum(col_j * weight_j)/sum(weight_j)
```

```mermaid
flowchart TD
    A[deltas + sample weights] --> B[sort per dimension]
    B --> C[trim tails]
    C --> D[weighted mean]
    D --> E[aggregated delta]
```

### `v2x_protocol.py`

#### `DynamicCryptoAgilityLayer._agility_score(recommended_mode)`

```text
avg_rtt = mean(rtt_history)
mps = msg_count / window_sec
latency_component = min(1, avg_rtt/latency_hi_ms)
traffic_component = min(1, mps/traffic_hi_mps)
score = wL*latency_component + wT*traffic_component
```

```mermaid
flowchart TD
    A[rtt history] --> B[latency component]
    C[msg timestamps] --> D[traffic component]
    B --> E[weighted sum score]
    D --> E
```

#### `DynamicCryptoAgilityLayer.maybe_switch_mode(...)`

```text
if mode=DILITHIUM and score>=up_thr -> target=SHA3
if mode=SHA3 and score<=down_thr -> target=DILITHIUM
switch only after confirm_count and switch_interval_sec
```

```mermaid
flowchart TD
    A[current mode + score] --> B[target mode decision]
    B --> C[pending confirmation count]
    C --> D{count ok and interval ok?}
    D -- yes --> E[switch]
    D -- no --> F[keep]
```

#### `V2XHub._recommend_crypto_mode()`

```text
score = 0.5*traffic_ratio + 0.3*client_load_ratio + 0.2*latency_ratio
mode = SHA3 if score>=0.66 else DILITHIUM
```

```mermaid
flowchart TD
    A[messages/sec] --> B[traffic ratio]
    C[clients] --> D[load ratio]
    E[latency hint] --> F[latency ratio]
    B --> G[weighted score]
    D --> G
    F --> G
    G --> H[mode choose]
```

### `network_overhead_analysis.py`

#### `analyze()`

```text
overhead_pct = ((protocol_bytes - plain_bytes) / plain_bytes) * 100
```

Applied for:
- `protocol_no_mac_bytes`
- `protocol_hmac_bytes`
- `encrypted_hmac_bytes`

```mermaid
flowchart TD
    A[plain payload bytes] --> B[protocol bytes]
    B --> C[subtract]
    A --> D[divide]
    C --> D
    D --> E[*100 overhead%]
```

### `did_identity.py`

#### `_msg_bits(message)`

```text
digest = SHA3-256(message)
bits[i] = (byte >> shift) & 1
```

```mermaid
flowchart TD
    A[message] --> B[SHA3 digest bytes]
    B --> C[bit extraction loop]
    C --> D[256 bits]
```

#### `verify_did_proof(challenge, proof, did_document)`

```text
challenge_hash == SHA3-256(challenge)
for each i: SHA3(signature[i]) == public_pairs[i][bit_i]
```

```mermaid
flowchart TD
    A[challenge/proof/doc] --> B[hash challenge check]
    B --> C[bitwise Lamport verify loop]
    C --> D{all matched?}
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
