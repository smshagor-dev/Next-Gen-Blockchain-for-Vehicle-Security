package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) *apiServer {
	t.Helper()
	server, err := newAPIServer([]byte(strings.Repeat("k", 48)), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func signedRequest(t *testing.T, s *apiServer, method, path string, body []byte, ts time.Time, nonce string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:55000"
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	timestamp := strconv.FormatInt(ts.Unix(), 10)
	hash := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(hash[:])
	req.Header.Set("X-SmartCar-Timestamp", timestamp)
	req.Header.Set("X-SmartCar-Nonce", nonce)
	req.Header.Set("X-SmartCar-Content-SHA256", bodyHash)
	req.Header.Set("X-SmartCar-Signature", s.expectedSignature(method, path, timestamp, nonce, bodyHash))
	return req
}

func initServer(t *testing.T, s *apiServer) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"vehicle_id":   "vehicle-test-001",
		"password":     strings.Repeat("p", 24),
		"auth_token":   strings.Repeat("a", 24),
		"recovery_key": strings.Repeat("r", 48),
		"chain_file":   "logs/test-chain.json",
	})
	req := signedRequest(t, s, http.MethodPost, "/init", body, time.Now(), strings.Repeat("01", 16))
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("init status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSHA3VectorABC(t *testing.T) {
	got := sha3s("abc")
	want := "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
	if got != want {
		t.Fatalf("sha3-256 mismatch: got %s want %s", got, want)
	}
}

func TestNewAPIServerRejectsWeakSecret(t *testing.T) {
	if _, err := newAPIServer([]byte("short"), t.TempDir()); err == nil {
		t.Fatal("expected weak secret rejection")
	}
}

func TestHealthRequiresChallengeAndReturnsProof(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing challenge status=%d", rr.Code)
	}

	challenge := strings.Repeat("ab", 16)
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("X-SmartCar-Challenge", challenge)
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	proof, _ := payload["service_proof"].(string)
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte("health:" + challenge))
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(proof), []byte(want)) {
		t.Fatal("service proof mismatch")
	}
}

func TestUnsignedMutationRejectedWithoutStateChange(t *testing.T) {
	s := testServer(t)
	initServer(t, s)
	req := httptest.NewRequest(http.MethodPost, "/emergency/brake", strings.NewReader(`{"distance":4}`))
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	s.state.mu.RLock()
	active := s.state.EmergencyBrakeActive
	s.state.mu.RUnlock()
	if active {
		t.Fatal("unauthorized request changed emergency brake state")
	}
}

func TestReplayRejected(t *testing.T) {
	s := testServer(t)
	initServer(t, s)
	body := []byte(`{}`)
	nonce := strings.Repeat("02", 16)
	req := signedRequest(t, s, http.MethodPost, "/engine/stop", body, time.Now(), nonce)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = signedRequest(t, s, http.MethodPost, "/engine/stop", body, time.Now(), nonce)
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("replay status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStaleSignedRequestRejected(t *testing.T) {
	s := testServer(t)
	body := []byte(`{}`)
	req := signedRequest(t, s, http.MethodPost, "/init", body, time.Now().Add(-2*defaultReplayWindow), strings.Repeat("03", 16))
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("stale status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWrongMethodRejected(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/engine/start", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestChainPathConfinedToDataDir(t *testing.T) {
	s := testServer(t)
	target, err := s.safeChainPath("../../etc/passwd.json", "vehicle")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(target) != s.dataDir || filepath.Base(target) != "passwd.json" {
		t.Fatalf("unsafe target=%s dataDir=%s", target, s.dataDir)
	}
}

func TestInitCannotReconfigureRuntime(t *testing.T) {
	s := testServer(t)
	initServer(t, s)
	body, _ := json.Marshal(map[string]any{
		"vehicle_id":   "attacker-vehicle",
		"password":     strings.Repeat("p", 24),
		"auth_token":   strings.Repeat("a", 24),
		"recovery_key": strings.Repeat("r", 48),
		"chain_file":   "other.json",
	})
	req := signedRequest(t, s, http.MethodPost, "/init", body, time.Now(), strings.Repeat("04", 16))
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	s.state.mu.RLock()
	id := s.state.VehicleID
	s.state.mu.RUnlock()
	if id != "vehicle-test-001" {
		t.Fatalf("runtime identity changed to %s", id)
	}
}

func TestMalformedEmergencyBodyCannotActivateBrake(t *testing.T) {
	s := testServer(t)
	initServer(t, s)
	body := []byte(`{"unexpected":true}`)
	req := signedRequest(t, s, http.MethodPost, "/emergency/brake", body, time.Now(), strings.Repeat("05", 16))
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	s.state.mu.RLock()
	active := s.state.EmergencyBrakeActive
	s.state.mu.RUnlock()
	if active {
		t.Fatal("malformed body activated brake")
	}
}
