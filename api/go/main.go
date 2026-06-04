package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
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
	ChainFile            string  `json:"-"`
	CarUnlocked          bool    `json:"car_unlocked"`
	EngineStarted        bool    `json:"engine_started"`
	EmergencyBrakeActive bool    `json:"emergency_brake_active"`
	SafeModeActive       bool    `json:"safe_mode_active"`
	Chain                []Block `json:"chain"`
}

var state = &State{
	VehicleID: "SMARTCAR_VIN_2024_BD_XYZ789",
	AuthToken: "SECURE_AUTH_TOKEN_SHA3_2024",
	Password:  "SmartCarSecretKey2024!@#",
	ChainFile: "logs/blockchain_gui_go.json",
}

func sha2s(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha3s(s string) string {
	sum := sha3.Sum256([]byte(s))
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

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func readJSON(r *http.Request, dst any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return false
	}
	return true
}

func handleInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VehicleID string `json:"vehicle_id"`
		Password  string `json:"password"`
		AuthToken string `json:"auth_token"`
		ChainFile string `json:"chain_file"`
	}
	if !readJSON(r, &req) {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	oldVehicleID := state.VehicleID
	oldChainFile := state.ChainFile
	if req.VehicleID != "" {
		state.VehicleID = req.VehicleID
	}
	if req.Password != "" {
		state.Password = req.Password
	}
	if req.AuthToken != "" {
		state.AuthToken = req.AuthToken
	}
	if req.ChainFile != "" {
		state.ChainFile = req.ChainFile
	}
	if oldVehicleID != state.VehicleID || oldChainFile != state.ChainFile {
		state.CarUnlocked = false
		state.EngineStarted = false
		state.EmergencyBrakeActive = false
		state.SafeModeActive = false
		state.Chain = nil
	}
	if len(state.Chain) == 0 {
		genesis := TelemetryData{Timestamp: nowISO(), ObstacleDistance: 999, FuelLevel: 100}
		b := state.addBlock(genesis, "GENESIS:GO_BACKEND")
		b.PreviousHash = "0"
		b.BlockHash = computeBlockHash(b)
		b.DualHashCombined = sha2s(b.BlockHash) + ":" + sha3s(b.BlockHash)
		state.Chain[0] = b
	}
	writeJSON(w, map[string]any{"ok": true, "backend": "go"})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	writeJSON(w, state)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !readJSON(r, &req) {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if hmac.Equal([]byte(req.Token), []byte(state.AuthToken)) {
		state.CarUnlocked = true
		state.addBlock(TelemetryData{Timestamp: nowISO()}, "AUTH:SUCCESS")
		writeJSON(w, map[string]any{"success": true, "message": "Authentication successful"})
		return
	}
	state.addBlock(TelemetryData{Timestamp: nowISO()}, "AUTH:FAILED")
	writeJSON(w, map[string]any{"success": false, "message": "Authentication failed"})
}

func handleSimple(event string, mutate func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if mutate != nil {
			mutate()
		}
		state.addBlock(TelemetryData{Timestamp: nowISO()}, event)
		writeJSON(w, map[string]any{"success": true, "message": event})
	}
}

func handleStartEngine(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.CarUnlocked {
		state.addBlock(TelemetryData{Timestamp: nowISO()}, "ENGINE:START_DENIED:LOCKED")
		writeJSON(w, map[string]any{"success": false, "message": "Vehicle locked"})
		return
	}
	state.EngineStarted = true
	state.addBlock(TelemetryData{Timestamp: nowISO()}, "ENGINE:STARTED")
	writeJSON(w, map[string]any{"success": true, "message": "Engine started"})
}

func handleTelemetry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Event     string        `json:"event"`
		Telemetry TelemetryData `json:"telemetry"`
	}
	if !readJSON(r, &req) {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if req.Telemetry.DriverUnwell || req.Telemetry.DriverDrowsinessScore >= 0.78 || req.Telemetry.DriverHeartRateBPM >= 125 {
		state.SafeModeActive = true
	}
	if req.Telemetry.EmergencyBrakeActive {
		state.EmergencyBrakeActive = true
	}
	block := state.addBlock(req.Telemetry, req.Event)
	writeJSON(w, map[string]any{"success": true, "block": block})
}

func handleEmergencyBrake(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Distance float64 `json:"distance"`
	}
	_ = readJSON(r, &req)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.EmergencyBrakeActive = true
	t := TelemetryData{Timestamp: nowISO(), ObstacleDistance: req.Distance, EmergencyBrakeActive: true, BrakePressure: 100}
	state.addBlock(t, fmt.Sprintf("EMERGENCY:MANUAL_BRAKE:OBSTACLE_%.1fM", req.Distance))
	writeJSON(w, map[string]any{"success": true})
}

func handleRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key             string `json:"key"`
		ForceChainReset bool   `json:"force_chain_reset"`
	}
	_ = readJSON(r, &req)
	state.mu.Lock()
	defer state.mu.Unlock()
	if req.Key == state.Password {
		state.CarUnlocked = true
		state.addBlock(TelemetryData{Timestamp: nowISO()}, "RECOVERY:OWNER_UNLOCK:CHAIN_VALID")
		writeJSON(w, map[string]any{"success": true})
		return
	}
	state.addBlock(TelemetryData{Timestamp: nowISO()}, "RECOVERY:OWNER_FAIL:INVALID_KEY")
	writeJSON(w, map[string]any{"success": false, "message": "Invalid recovery key"})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	writeJSON(w, map[string]any{"valid": state.verifyLocked()})
}

func handleSave(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	payload, err := json.MarshalIndent(state.Chain, "", "  ")
	target := state.ChainFile
	state.mu.RUnlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(target, payload, 0644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"success": true, "file": target})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]any{"ok": true}) })
	mux.HandleFunc("/init", handleInit)
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/auth", handleAuth)
	mux.HandleFunc("/engine/start", handleStartEngine)
	mux.HandleFunc("/engine/stop", handleSimple("ENGINE:STOPPED", func() { state.EngineStarted = false }))
	mux.HandleFunc("/vehicle/lock", handleSimple("VEHICLE:LOCKED", func() {
		state.CarUnlocked = false
		state.EngineStarted = false
	}))
	mux.HandleFunc("/telemetry", handleTelemetry)
	mux.HandleFunc("/emergency/brake", handleEmergencyBrake)
	mux.HandleFunc("/recovery/unlock", handleRecovery)
	mux.HandleFunc("/verify", handleVerify)
	mux.HandleFunc("/save", handleSave)
	log.Println("SmartCar Go backend listening on 127.0.0.1:8787")
	log.Fatal(http.ListenAndServe("127.0.0.1:8787", mux))
}
