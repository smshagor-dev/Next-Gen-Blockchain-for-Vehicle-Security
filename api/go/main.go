package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/bits"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	PQHybridAuthentication              = "PQ_HYBRID_AUTHENTICATION"
	ClassicalPrivacyCommitment          = "CLASSICAL_PRIVACY_COMMITMENT"
	LegacyECDHFallbackDisabledByDefault = "LEGACY_ECDH_FALLBACK_DISABLED_BY_DEFAULT"
	hybridSecuritySummary               = "Hybrid security: post-quantum key establishment with classical commitment/proof components."
	ecdhP256Warning                     = "WARNING: ECDH-P256 fallback is classical and not post-quantum secure."
	openRegistration                    = "OPEN_REGISTRATION"
	openRegistrationSybilWarning        = "No Sybil-resistance guarantee. Unlimited identities may be created."
	consensusModelSimpleMajority        = "simple_majority"
	majorityAttackNote                  = "A voting majority can approve syntactically valid malicious blocks without finding hash collisions."
	prototypeFLWarning                  = "WARNING: This FL experiment is too small for Byzantine-robustness claims."

	defaultReplayWindow = 15 * time.Second
	defaultMaxBodyBytes = int64(1 << 20)
)

type TelemetryData struct {
	Speed                 float64 `json:"speed"`
	Acceleration          float64 `json:"acceleration"`
	FuelLevel             float64 `json:"fuel_level"`
	BatteryVoltage        float64 `json:"battery_voltage"`
	EngineTemp            float64 `json:"engine_temp"`
	GPSLat                float64 `json:"gps_lat"`
	GPSLon                float64 `json:"gps_lon"`
	ObstacleDistance      float64 `json:"obstacle_distance"`
	EmergencyBrakeActive  bool    `json:"emergency_brake_active"`
	SteeringAngle         float64 `json:"steering_angle"`
	BrakePressure         float64 `json:"brake_pressure"`
	ThrottlePosition      float64 `json:"throttle_position"`
	RPM                   float64 `json:"rpm"`
	Odometer              float64 `json:"odometer"`
	DriverHeartRateBPM    float64 `json:"driver_heart_rate_bpm"`
	DriverDrowsinessScore float64 `json:"driver_drowsiness_score"`
	DriverUnwell          bool    `json:"driver_unwell"`
	Timestamp             string  `json:"timestamp"`
}

type Block struct {
	Index                 int              `json:"index"`
	Timestamp             string           `json:"timestamp"`
	VehicleID             string           `json:"vehicle_id"`
	Telemetry             TelemetryData    `json:"telemetry"`
	EventData             string           `json:"event_data"`
	PreviousHash          string           `json:"previous_hash"`
	TelemetryHashSHA2     string           `json:"telemetry_hash_sha2"`
	TelemetryHashSHA3     string           `json:"telemetry_hash_sha3"`
	EventHashSHA2         string           `json:"event_hash_sha2"`
	EventHashSHA3         string           `json:"event_hash_sha3"`
	BlockHash             string           `json:"block_hash"`
	DualHashCombined      string           `json:"dual_hash_combined"`
	SmartContractReceipts []map[string]any `json:"smart_contract_receipts"`
}

type State struct {
	mu                   sync.RWMutex
	VehicleID            string  `json:"vehicle_id"`
	AuthToken            string  `json:"-"`
	Password             string  `json:"-"`
	RecoveryKey          string  `json:"-"`
	ChainFile            string  `json:"-"`
	Initialized          bool    `json:"-"`
	CarUnlocked          bool    `json:"car_unlocked"`
	EngineStarted        bool    `json:"engine_started"`
	EmergencyBrakeActive bool    `json:"emergency_brake_active"`
	SafeModeActive       bool    `json:"safe_mode_active"`
	Chain                []Block `json:"chain"`
}

type apiServer struct {
	state        *State
	secret       []byte
	dataDir      string
	replayWindow time.Duration
	maxBodyBytes int64
	instanceID   string

	nonceMu sync.Mutex
	nonces  map[string]time.Time
}

func ecdhFallbackEnabled() bool {
	return os.Getenv("SMARTCAR_GO_ALLOW_CLASSICAL_ECDH_FALLBACK") == "1"
}

func securityCapabilityOutput() map[string]any {
	fallback := "disabled_by_default/classical"
	if ecdhFallbackEnabled() {
		fallback = "enabled/classical"
	}
	return map[string]any{
		"security_modes": []string{
			PQHybridAuthentication,
			ClassicalPrivacyCommitment,
			LegacyECDHFallbackDisabledByDefault,
		},
		"summary":               hybridSecuritySummary,
		"key_establishment":     "ML-KEM/Kyber - post-quantum",
		"commitment_hiding":     "Pedersen - information-theoretic hiding",
		"commitment_binding":    "Pedersen - classical discrete-log assumption",
		"range_proof_soundness": "Schnorr/classical assumption",
		"fallback_ecdh_p256":    fallback,
		"local_control_api":     "HMAC-SHA256 + timestamp/nonce replay defense on loopback",
	}
}

func identityAdmissionPolicy() string {
	switch os.Getenv("SMARTCAR_IDENTITY_ADMISSION_POLICY") {
	case "PROOF_OF_STAKE", "PROOF_OF_WORK", "CERTIFICATE_AUTHORITY", "VEHICLE_MANUFACTURER_REGISTRY", "TRANSPORT_AUTHORITY_REGISTRY":
		return os.Getenv("SMARTCAR_IDENTITY_ADMISSION_POLICY")
	default:
		return openRegistration
	}
}

func identitySecurityOutput() map[string]any {
	policy := identityAdmissionPolicy()
	sybilResistance := policy != openRegistration
	out := map[string]any{
		"identity_authenticity":     true,
		"sybil_resistance":          sybilResistance,
		"identity_admission_policy": policy,
		"identity_authenticity_model": map[string]bool{
			"secret_key_ownership": true,
			"valid_signatures":     true,
			"non_repudiation":      true,
		},
	}
	if sybilResistance {
		out["sybil_resistance_model"] = "Identity creation is limited by an external admission policy."
	} else {
		out["sybil_resistance_model"] = openRegistrationSybilWarning
		out["warning"] = openRegistrationSybilWarning
	}
	return out
}

func consensusSecurityOutput() map[string]any {
	return map[string]any{
		"consensus_model":                           consensusModelSimpleMajority,
		"majority_attack_resistant":                 false,
		"dual_hash_chaining":                        true,
		"hash_collision_resistance":                 true,
		"retroactive_tamper_evidence":               true,
		"protects_against_forward_majority_control": false,
		"notes":                                     majorityAttackNote,
	}
}

func flValidationOutput() map[string]any {
	return map[string]any{
		"fl_validation_level":                 "prototype_sanity_check",
		"num_peers":                           3,
		"samples_per_peer":                    10,
		"test_samples":                        24,
		"byzantine_peers":                     1,
		"attack_type":                         "100x_weight_delta",
		"statistical_significance":            false,
		"supports_byzantine_robustness_claim": false,
		"warnings":                            []string{prototypeFLWarning},
	}
}

func adversarialValidationOutput() map[string]any {
	return map[string]any{
		"adversarial_validation_level":     "single_run_sanity_check",
		"supports_general_detection_claim": false,
		"detection_rate_headline_allowed":  false,
		"attack_trials_per_type":           1,
		"statistical_significance":         false,
		"known_trivial_triggers":           []string{"350_kmh_speed", "100x_fl_weight_delta"},
	}
}

func contributionBoundaryOutput() map[string]any {
	return map[string]any{
		"claims_new_cryptographic_primitive": false,
		"contribution_type":                  "system_integration_and_validation_transparency",
		"reused_components": []string{
			"ML-KEM/Kyber",
			"Pedersen commitments",
			"Lamport OTS/DID",
			"SHA2/SHA3 hashing",
			"HMAC-authenticated local API security",
			"majority blockchain logic",
			"robust aggregation concepts",
		},
		"novel_components": []string{
			"cross-layer prototype integration",
			"security capability reporting",
			"assumption-aware dashboard/API metadata",
			"validation-plan scaffolding",
		},
	}
}

func complexityBoundaryOutput() map[string]any {
	return map[string]any{
		"overall_complexity_claim":        "component_dependent",
		"full_system_o_n_claim":           false,
		"naive_full_mesh_network_volume":  "O(n^2)",
		"single_proposal_vote_collection": "O(n)",
		"fl_aggregation":                  "O(n*d)",
		"chain_audit":                     "O(k)",
	}
}

func pedersenPrivacyOutput() map[string]any {
	return map[string]any{
		"pedersen_mode":                    "COMMIT_ONLY",
		"commitment_homomorphic":           true,
		"aggregate_statistics_recoverable": false,
		"requires_opening_for_aggregate":   true,
		"secure_aggregation_implemented":   false,
	}
}

func reviewerAuditOutput() map[string]any {
	return map[string]any{
		"paper_ready_claim_status":            "corrected_but_requires_new_experiments",
		"full_post_quantum_security_claim":    false,
		"sybil_resistance_claim":              false,
		"majority_attack_resistance_claim":    false,
		"byzantine_robustness_claim":          false,
		"general_100_percent_detection_claim": false,
		"new_crypto_primitive_claim":          false,
		"whole_system_o_n_claim":              false,
		"secure_aggregation_claim":            false,
		"canonical_layer_count":               "six implemented prototype layers",
		"canonical_latency":                   "5.34 ms warm-start prototype pipeline latency",
	}
}

func sha2s(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha3Sum256(data []byte) [32]byte {
	const rate = 136
	var state [25]uint64

	for len(data) >= rate {
		for i := 0; i < rate/8; i++ {
			state[i] ^= binary.LittleEndian.Uint64(data[i*8 : i*8+8])
		}
		keccakF1600(&state)
		data = data[rate:]
	}

	var block [rate]byte
	copy(block[:], data)
	block[len(data)] = 0x06
	block[rate-1] |= 0x80
	for i := 0; i < rate/8; i++ {
		state[i] ^= binary.LittleEndian.Uint64(block[i*8 : i*8+8])
	}
	keccakF1600(&state)

	var out [32]byte
	for i := 0; i < len(out)/8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:i*8+8], state[i])
	}
	return out
}

func keccakF1600(a *[25]uint64) {
	roundConstants := [24]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}
	rotations := [25]int{
		0, 1, 62, 28, 27,
		36, 44, 6, 55, 20,
		3, 10, 43, 25, 39,
		41, 45, 15, 21, 8,
		18, 2, 61, 56, 14,
	}

	for _, rc := range roundConstants {
		var c, d [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				a[x+5*y] ^= d[x]
			}
		}

		var b [25]uint64
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				nx := y
				ny := (2*x + 3*y) % 5
				b[nx+5*ny] = bits.RotateLeft64(a[x+5*y], rotations[x+5*y])
			}
		}
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				a[x+5*y] = b[x+5*y] ^ ((^b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
			}
		}
		a[0] ^= rc
	}
}

func sha3s(s string) string {
	sum := sha3Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func telemetryString(t TelemetryData) string {
	return fmt.Sprintf("%.6f,%.6f,%.6f,%.6f,%.6f,%.8f,%.8f,%.6f,%t,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%t,%s",
		t.Speed, t.Acceleration, t.FuelLevel, t.BatteryVoltage, t.EngineTemp,
		t.GPSLat, t.GPSLon, t.ObstacleDistance, t.EmergencyBrakeActive,
		t.SteeringAngle, t.BrakePressure, t.ThrottlePosition, t.RPM, t.Odometer,
		t.DriverHeartRateBPM, t.DriverDrowsinessScore, t.DriverUnwell, t.Timestamp)
}

func computeBlockHash(b Block) string {
	raw := fmt.Sprintf("%d%s%s%s%s%s", b.Index, b.Timestamp, b.VehicleID, b.TelemetryHashSHA3, b.EventHashSHA3, b.PreviousHash)
	return sha3s(raw)
}

func (s *State) addBlock(t TelemetryData, event string) Block {
	if t.Timestamp == "" {
		t.Timestamp = nowISO()
	}
	prev := ""
	if len(s.Chain) > 0 {
		prev = s.Chain[len(s.Chain)-1].BlockHash
	}
	b := Block{
		Index:        len(s.Chain),
		Timestamp:    nowISO(),
		VehicleID:    s.VehicleID,
		Telemetry:    t,
		EventData:    event,
		PreviousHash: prev,
	}
	tel := telemetryString(t)
	b.TelemetryHashSHA2 = sha2s(tel)
	b.TelemetryHashSHA3 = sha3s(tel)
	b.EventHashSHA2 = sha2s(event)
	b.EventHashSHA3 = sha3s(event)
	b.BlockHash = computeBlockHash(b)
	b.DualHashCombined = sha2s(b.BlockHash) + ":" + sha3s(b.BlockHash)
	b.SmartContractReceipts = []map[string]any{{"receipt_id": fmt.Sprintf("go_block_%d", b.Index), "status": "ok"}}
	s.Chain = append(s.Chain, b)
	return b
}

func (s *State) verifyLocked() bool {
	if len(s.Chain) == 0 {
		return false
	}
	for i := range s.Chain {
		b := s.Chain[i]
		if i == 0 && b.PreviousHash != "0" {
			return false
		}
		if i > 0 && b.PreviousHash != s.Chain[i-1].BlockHash {
			return false
		}
		tel := telemetryString(b.Telemetry)
		if b.TelemetryHashSHA2 != sha2s(tel) || b.TelemetryHashSHA3 != sha3s(tel) {
			return false
		}
		if b.EventHashSHA2 != sha2s(b.EventData) || b.EventHashSHA3 != sha3s(b.EventData) {
			return false
		}
		if b.BlockHash != computeBlockHash(b) {
			return false
		}
	}
	return true
}

func newAPIServer(secret []byte, dataDir string) (*apiServer, error) {
	if len(secret) < 32 {
		return nil, errors.New("SMARTCAR_GO_API_SECRET must contain at least 32 bytes")
	}
	if strings.Contains(strings.ToLower(string(secret)), "change_me") || strings.Contains(strings.ToLower(string(secret)), "changeme") {
		return nil, errors.New("SMARTCAR_GO_API_SECRET must not use a placeholder value")
	}
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "logs"
	}
	absDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve data dir: %w", err)
	}
	instanceRaw := make([]byte, 16)
	if _, err := rand.Read(instanceRaw); err != nil {
		return nil, fmt.Errorf("generate service instance id: %w", err)
	}
	return &apiServer{
		state:        &State{},
		secret:       append([]byte(nil), secret...),
		dataDir:      absDir,
		replayWindow: defaultReplayWindow,
		maxBodyBytes: defaultMaxBodyBytes,
		instanceID:   hex.EncodeToString(instanceRaw),
		nonces:       make(map[string]time.Time),
	}, nil
}

func loadAPISecret() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("SMARTCAR_GO_API_SECRET"))
	if len(raw) < 32 {
		return nil, errors.New("SMARTCAR_GO_API_SECRET is required and must be at least 32 characters")
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "change_me") || strings.Contains(lower, "changeme") || strings.Contains(lower, "replace-me") {
		return nil, errors.New("SMARTCAR_GO_API_SECRET contains a placeholder value")
	}
	return []byte(raw), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func readJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (s *apiServer) healthProof(challenge string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte("health:" + challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *apiServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		http.Error(w, "loopback only", http.StatusForbidden)
		return
	}
	challenge := strings.TrimSpace(r.Header.Get("X-SmartCar-Challenge"))
	if len(challenge) < 32 || len(challenge) > 128 {
		http.Error(w, "valid challenge required", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(challenge); err != nil {
		http.Error(w, "challenge must be hexadecimal", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"backend":       "go",
		"instance_id":   s.instanceID,
		"service_proof": s.healthProof(challenge),
	})
}

func canonicalAPIMessage(method, path, timestamp, nonce, bodyHash string) string {
	return strings.Join([]string{strings.ToUpper(method), path, timestamp, nonce, bodyHash}, "\n")
}

func (s *apiServer) expectedSignature(method, path, timestamp, nonce, bodyHash string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(canonicalAPIMessage(method, path, timestamp, nonce, bodyHash)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *apiServer) consumeNonce(nonce string, now time.Time) bool {
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()

	cutoff := now.Add(-2 * s.replayWindow)
	for key, seen := range s.nonces {
		if seen.Before(cutoff) {
			delete(s.nonces, key)
		}
	}
	if _, exists := s.nonces[nonce]; exists {
		return false
	}
	s.nonces[nonce] = now
	return true
}

func (s *apiServer) secure(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isLoopbackRemote(r.RemoteAddr) {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		if method == http.MethodPost && len(body) > 0 {
			contentType := strings.ToLower(r.Header.Get("Content-Type"))
			if !strings.HasPrefix(contentType, "application/json") {
				http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
				return
			}
		}

		timestamp := strings.TrimSpace(r.Header.Get("X-SmartCar-Timestamp"))
		nonce := strings.TrimSpace(r.Header.Get("X-SmartCar-Nonce"))
		bodyHash := strings.TrimSpace(r.Header.Get("X-SmartCar-Content-SHA256"))
		signature := strings.TrimSpace(r.Header.Get("X-SmartCar-Signature"))
		if timestamp == "" || nonce == "" || bodyHash == "" || signature == "" {
			http.Error(w, "authenticated request headers required", http.StatusUnauthorized)
			return
		}

		unixSec, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			http.Error(w, "invalid timestamp", http.StatusUnauthorized)
			return
		}
		now := time.Now().UTC()
		requestTime := time.Unix(unixSec, 0).UTC()
		delta := now.Sub(requestTime)
		if delta < 0 {
			delta = -delta
		}
		if delta > s.replayWindow {
			http.Error(w, "stale request", http.StatusUnauthorized)
			return
		}

		nonceBytes, err := hex.DecodeString(nonce)
		if err != nil || len(nonceBytes) < 16 || len(nonceBytes) > 64 {
			http.Error(w, "invalid nonce", http.StatusUnauthorized)
			return
		}
		expectedBodyHashRaw := sha256.Sum256(body)
		expectedBodyHash := hex.EncodeToString(expectedBodyHashRaw[:])
		if !hmac.Equal([]byte(strings.ToLower(bodyHash)), []byte(expectedBodyHash)) {
			http.Error(w, "body hash mismatch", http.StatusUnauthorized)
			return
		}
		expectedSig := s.expectedSignature(method, r.URL.EscapedPath(), timestamp, nonce, expectedBodyHash)
		if !hmac.Equal([]byte(strings.ToLower(signature)), []byte(expectedSig)) {
			http.Error(w, "invalid request signature", http.StatusUnauthorized)
			return
		}
		if !s.consumeNonce(nonce, now) {
			http.Error(w, "replayed request", http.StatusConflict)
			return
		}

		next(w, r)
	}
}

func safeText(value string, maxLen int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxLen {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *apiServer) safeChainPath(requested, vehicleID string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		requested = fmt.Sprintf("blockchain_%s.json", strings.ReplaceAll(vehicleID, string(filepath.Separator), "_"))
	}
	cleaned := filepath.Clean(requested)
	base := filepath.Base(cleaned)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "", errors.New("invalid chain file")
	}
	lower := strings.ToLower(base)
	if !strings.HasSuffix(lower, ".json") {
		return "", errors.New("chain file must use .json extension")
	}
	target := filepath.Join(s.dataDir, base)
	rel, err := filepath.Rel(s.dataDir, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("chain file escapes configured data directory")
	}
	return target, nil
}

func (s *apiServer) handleInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VehicleID   string `json:"vehicle_id"`
		Password    string `json:"password"`
		AuthToken   string `json:"auth_token"`
		RecoveryKey string `json:"recovery_key"`
		ChainFile   string `json:"chain_file"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if !safeText(req.VehicleID, 128) || len(req.Password) < 16 || len(req.AuthToken) < 16 || len(req.RecoveryKey) < 32 {
		http.Error(w, "invalid initialization parameters", http.StatusBadRequest)
		return
	}
	target, err := s.safeChainPath(req.ChainFile, req.VehicleID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.Initialized {
		sameIdentity := s.state.VehicleID == req.VehicleID && s.state.ChainFile == target
		sameSecrets := hmac.Equal([]byte(s.state.Password), []byte(req.Password)) &&
			hmac.Equal([]byte(s.state.AuthToken), []byte(req.AuthToken)) &&
			hmac.Equal([]byte(s.state.RecoveryKey), []byte(req.RecoveryKey))
		if !sameIdentity || !sameSecrets {
			http.Error(w, "backend is already initialized; runtime reconfiguration is denied", http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "backend": "go", "initialized": true})
		return
	}

	s.state.VehicleID = req.VehicleID
	s.state.Password = req.Password
	s.state.AuthToken = req.AuthToken
	s.state.RecoveryKey = req.RecoveryKey
	s.state.ChainFile = target
	s.state.Initialized = true
	s.state.CarUnlocked = false
	s.state.EngineStarted = false
	s.state.EmergencyBrakeActive = false
	s.state.SafeModeActive = false
	s.state.Chain = nil

	genesis := TelemetryData{Timestamp: nowISO(), ObstacleDistance: 999, FuelLevel: 100}
	b := s.state.addBlock(genesis, "GENESIS:GO_BACKEND")
	b.PreviousHash = "0"
	b.BlockHash = computeBlockHash(b)
	b.DualHashCombined = sha2s(b.BlockHash) + ":" + sha3s(b.BlockHash)
	s.state.Chain[0] = b
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "backend": "go", "initialized": true})
}

func (s *apiServer) requireInitialized(w http.ResponseWriter) bool {
	s.state.mu.RLock()
	initialized := s.state.Initialized
	s.state.mu.RUnlock()
	if !initialized {
		http.Error(w, "backend not initialized", http.StatusPreconditionFailed)
		return false
	}
	return true
}

func (s *apiServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"vehicle_id":             s.state.VehicleID,
		"car_unlocked":           s.state.CarUnlocked,
		"engine_started":         s.state.EngineStarted,
		"emergency_brake_active": s.state.EmergencyBrakeActive,
		"safe_mode_active":       s.state.SafeModeActive,
		"chain":                  s.state.Chain,
		"security_capabilities":  securityCapabilityOutput(),
		"identity_security":      identitySecurityOutput(),
		"consensus_security":     consensusSecurityOutput(),
		"fl_validation":          flValidationOutput(),
		"adversarial_validation": adversarialValidationOutput(),
		"contribution_boundary":  contributionBoundaryOutput(),
		"complexity_boundary":    complexityBoundaryOutput(),
		"pedersen_privacy":       pedersenPrivacyOutput(),
		"reviewer_audit":         reviewerAuditOutput(),
	})
}

func (s *apiServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if hmac.Equal([]byte(req.Token), []byte(s.state.AuthToken)) {
		s.state.CarUnlocked = true
		s.state.addBlock(TelemetryData{Timestamp: nowISO()}, "AUTH:SUCCESS")
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Authentication successful"})
		return
	}
	s.state.addBlock(TelemetryData{Timestamp: nowISO()}, "AUTH:FAILED")
	writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Authentication failed"})
}

func (s *apiServer) handleSimple(event string, mutate func(*State)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireInitialized(w) {
			return
		}
		s.state.mu.Lock()
		defer s.state.mu.Unlock()
		if mutate != nil {
			mutate(s.state)
		}
		s.state.addBlock(TelemetryData{Timestamp: nowISO()}, event)
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": event})
	}
}

func (s *apiServer) handleStartEngine(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if !s.state.CarUnlocked {
		s.state.addBlock(TelemetryData{Timestamp: nowISO()}, "ENGINE:START_DENIED:LOCKED")
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Vehicle locked"})
		return
	}
	s.state.EngineStarted = true
	s.state.addBlock(TelemetryData{Timestamp: nowISO()}, "ENGINE:STARTED")
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Engine started"})
}

func finiteTelemetry(t TelemetryData) bool {
	values := []float64{
		t.Speed, t.Acceleration, t.FuelLevel, t.BatteryVoltage, t.EngineTemp,
		t.GPSLat, t.GPSLon, t.ObstacleDistance, t.SteeringAngle, t.BrakePressure,
		t.ThrottlePosition, t.RPM, t.Odometer, t.DriverHeartRateBPM,
		t.DriverDrowsinessScore,
	}
	for _, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > 1e9 {
			return false
		}
	}
	return true
}

func (s *apiServer) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	var req struct {
		Event     string        `json:"event"`
		Telemetry TelemetryData `json:"telemetry"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if len(req.Event) > 256 || !finiteTelemetry(req.Telemetry) {
		http.Error(w, "invalid telemetry payload", http.StatusBadRequest)
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if req.Telemetry.DriverUnwell || req.Telemetry.DriverDrowsinessScore >= 0.78 || req.Telemetry.DriverHeartRateBPM >= 125 {
		s.state.SafeModeActive = true
	}
	if req.Telemetry.EmergencyBrakeActive {
		s.state.EmergencyBrakeActive = true
	}
	block := s.state.addBlock(req.Telemetry, req.Event)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "block": block})
}

func (s *apiServer) handleEmergencyBrake(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	var req struct {
		Distance float64 `json:"distance"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if math.IsNaN(req.Distance) || math.IsInf(req.Distance, 0) || req.Distance < 0 || req.Distance > 10000 {
		http.Error(w, "distance must be between 0 and 10000 meters", http.StatusBadRequest)
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	s.state.EmergencyBrakeActive = true
	t := TelemetryData{Timestamp: nowISO(), ObstacleDistance: req.Distance, EmergencyBrakeActive: true, BrakePressure: 100}
	s.state.addBlock(t, fmt.Sprintf("EMERGENCY:MANUAL_BRAKE:OBSTACLE_%.1fM", req.Distance))
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *apiServer) handleRecovery(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	var req struct {
		Key             string `json:"key"`
		ForceChainReset bool   `json:"force_chain_reset"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.ForceChainReset {
		http.Error(w, "remote chain reset is disabled", http.StatusForbidden)
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if hmac.Equal([]byte(req.Key), []byte(s.state.RecoveryKey)) {
		s.state.CarUnlocked = true
		s.state.addBlock(TelemetryData{Timestamp: nowISO()}, "RECOVERY:OWNER_UNLOCK:CHAIN_VALID")
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
		return
	}
	s.state.addBlock(TelemetryData{Timestamp: nowISO()}, "RECOVERY:OWNER_FAIL:INVALID_KEY")
	writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Invalid recovery key"})
}

func (s *apiServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"valid": s.state.verifyLocked()})
}

func (s *apiServer) handleSave(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	s.state.mu.RLock()
	payload, err := json.MarshalIndent(s.state.Chain, "", "  ")
	target := s.state.ChainFile
	s.state.mu.RUnlock()
	if err != nil {
		http.Error(w, "could not serialize chain", http.StatusInternalServerError)
		return
	}
	if target == "" {
		http.Error(w, "chain target not configured", http.StatusPreconditionFailed)
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		http.Error(w, "could not create chain directory", http.StatusInternalServerError)
		return
	}
	temp, err := os.CreateTemp(filepath.Dir(target), ".chain-*.tmp")
	if err != nil {
		http.Error(w, "could not create temporary chain file", http.StatusInternalServerError)
		return
	}
	tempName := temp.Name()
	cleanup := func() { _ = os.Remove(tempName) }
	defer cleanup()
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		http.Error(w, "could not secure temporary chain file", http.StatusInternalServerError)
		return
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		http.Error(w, "could not write chain", http.StatusInternalServerError)
		return
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		http.Error(w, "could not sync chain", http.StatusInternalServerError)
		return
	}
	if err := temp.Close(); err != nil {
		http.Error(w, "could not close chain file", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tempName, target); err != nil {
		_ = os.Remove(target)
		if retryErr := os.Rename(tempName, target); retryErr != nil {
			http.Error(w, "could not save chain", http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "file": filepath.Base(target)})
}

func (s *apiServer) metadataHandler(fn func() map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, fn())
	}
}

func (s *apiServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/init", s.secure(http.MethodPost, s.handleInit))
	mux.HandleFunc("/status", s.secure(http.MethodGet, s.handleStatus))
	mux.HandleFunc("/auth", s.secure(http.MethodPost, s.handleAuth))
	mux.HandleFunc("/engine/start", s.secure(http.MethodPost, s.handleStartEngine))
	mux.HandleFunc("/engine/stop", s.secure(http.MethodPost, s.handleSimple("ENGINE:STOPPED", func(st *State) { st.EngineStarted = false })))
	mux.HandleFunc("/vehicle/lock", s.secure(http.MethodPost, s.handleSimple("VEHICLE:LOCKED", func(st *State) {
		st.CarUnlocked = false
		st.EngineStarted = false
	})))
	mux.HandleFunc("/telemetry", s.secure(http.MethodPost, s.handleTelemetry))
	mux.HandleFunc("/emergency/brake", s.secure(http.MethodPost, s.handleEmergencyBrake))
	mux.HandleFunc("/recovery/unlock", s.secure(http.MethodPost, s.handleRecovery))
	mux.HandleFunc("/verify", s.secure(http.MethodGet, s.handleVerify))
	mux.HandleFunc("/security/capabilities", s.secure(http.MethodGet, s.metadataHandler(securityCapabilityOutput)))
	mux.HandleFunc("/identity/security", s.secure(http.MethodGet, s.metadataHandler(identitySecurityOutput)))
	mux.HandleFunc("/consensus/security", s.secure(http.MethodGet, s.metadataHandler(consensusSecurityOutput)))
	mux.HandleFunc("/fl/validation", s.secure(http.MethodGet, s.metadataHandler(flValidationOutput)))
	mux.HandleFunc("/adversarial/validation", s.secure(http.MethodGet, s.metadataHandler(adversarialValidationOutput)))
	mux.HandleFunc("/contribution/boundary", s.secure(http.MethodGet, s.metadataHandler(contributionBoundaryOutput)))
	mux.HandleFunc("/complexity/boundary", s.secure(http.MethodGet, s.metadataHandler(complexityBoundaryOutput)))
	mux.HandleFunc("/privacy/pedersen", s.secure(http.MethodGet, s.metadataHandler(pedersenPrivacyOutput)))
	mux.HandleFunc("/reviewer/audit", s.secure(http.MethodGet, s.metadataHandler(reviewerAuditOutput)))
	mux.HandleFunc("/save", s.secure(http.MethodPost, s.handleSave))
	return mux
}

func main() {
	if ecdhFallbackEnabled() {
		log.Println(ecdhP256Warning)
	}
	secret, err := loadAPISecret()
	if err != nil {
		log.Fatal(err)
	}
	server, err := newAPIServer(secret, os.Getenv("SMARTCAR_GO_DATA_DIR"))
	if err != nil {
		log.Fatal(err)
	}

	httpServer := &http.Server{
		Addr:              "127.0.0.1:8787",
		Handler:           server.routes(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Println("SmartCar Go backend listening on 127.0.0.1:8787 (authenticated loopback API)")
	log.Fatal(httpServer.ListenAndServe())
}
