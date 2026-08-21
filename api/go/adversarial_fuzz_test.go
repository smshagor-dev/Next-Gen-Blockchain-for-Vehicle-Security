package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These fuzz targets are repo-local and use httptest only. They never send
// traffic to external hosts. Regular `go test` executes the seed corpus; CI
// additionally gives selected targets a short bounded fuzz window.

func FuzzControlAPIMalformedEmergency(f *testing.F) {
	f.Add([]byte(`{"distance":4}`))
	f.Add([]byte(`{"unexpected":true}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"distance":-1}`))
	f.Add([]byte(`{"distance":1000000000}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 2<<20 {
			t.Skip()
		}
		s := testServer(t)
		initServer(t, s)
		nonce := strings.Repeat("0a", 16)
		req := signedRequest(t, s, http.MethodPost, "/emergency/brake", body, time.Now(), nonce)
		rr := httptest.NewRecorder()
		s.routes().ServeHTTP(rr, req)

		if rr.Code >= 500 {
			t.Fatalf("malformed emergency request caused server error: status=%d body=%q", rr.Code, rr.Body.String())
		}
		if rr.Code != http.StatusOK {
			s.state.mu.RLock()
			active := s.state.EmergencyBrakeActive
			s.state.mu.RUnlock()
			if active {
				t.Fatal("rejected malformed emergency payload activated brake")
			}
		}
	})
}

func FuzzControlAPIUnsignedMutation(f *testing.F) {
	f.Add("/engine/start", []byte(`{}`))
	f.Add("/engine/stop", []byte(`{}`))
	f.Add("/vehicle/lock", []byte(`{}`))
	f.Add("/telemetry", []byte(`{"speed":1}`))
	f.Add("/recovery/unlock", []byte(`{}`))

	f.Fuzz(func(t *testing.T, path string, body []byte) {
		if len(path) > 256 || len(body) > 64<<10 {
			t.Skip()
		}
		allowed := map[string]bool{
			"/engine/start": true,
			"/engine/stop": true,
			"/vehicle/lock": true,
			"/telemetry": true,
			"/recovery/unlock": true,
			"/save": true,
			"/emergency/brake": true,
		}
		if !allowed[path] {
			return
		}

		s := testServer(t)
		initServer(t, s)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:50000"
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.routes().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("unsigned mutation path=%s status=%d body=%q", path, rr.Code, rr.Body.String())
		}
	})
}

func FuzzSafeChainPathConfined(f *testing.F) {
	f.Add("../../etc/passwd.json")
	f.Add("logs/chain.json")
	f.Add("C:\\Windows\\System32\\drivers\\etc\\hosts.json")
	f.Add("../outside/../../escape.json")
	f.Add("chain.json")

	f.Fuzz(func(t *testing.T, candidate string) {
		if len(candidate) > 4096 {
			t.Skip()
		}
		s := testServer(t)
		target, err := s.safeChainPath(candidate, "vehicle-fuzz")
		if err != nil {
			return
		}
		rel, err := filepath.Rel(s.dataDir, target)
		if err != nil {
			t.Fatal(err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			t.Fatalf("chain path escaped data dir: candidate=%q target=%q dataDir=%q", candidate, target, s.dataDir)
		}
		if filepath.Ext(target) != ".json" {
			t.Fatalf("accepted chain path without .json extension: %q", target)
		}
	})
}

func FuzzHealthChallengeParser(f *testing.F) {
	f.Add(strings.Repeat("ab", 16))
	f.Add("")
	f.Add("not-hex")
	f.Add("aa")
	f.Add(strings.Repeat("00", 64))

	f.Fuzz(func(t *testing.T, challenge string) {
		if len(challenge) > 8192 {
			t.Skip()
		}
		s := testServer(t)
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "127.0.0.1:50000"
		req.Header.Set("X-SmartCar-Challenge", challenge)
		rr := httptest.NewRecorder()
		s.routes().ServeHTTP(rr, req)
		if rr.Code >= 500 {
			t.Fatalf("health challenge caused server error: status=%d", rr.Code)
		}
	})
}
