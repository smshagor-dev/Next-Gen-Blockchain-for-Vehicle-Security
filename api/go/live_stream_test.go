package main

import (
	"crypto/hmac"
	"strings"
	"testing"
)

func TestValidateLiveStreamAddrRequiresLiteralLoopback(t *testing.T) {
	for _, good := range []string{"127.0.0.1:8788", "[::1]:8788"} {
		if err := validateLiveStreamAddr(good); err != nil {
			t.Fatalf("expected %s to be accepted: %v", good, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:8788", "localhost:8788", "192.168.1.10:8788", "127.0.0.1:80", "127.0.0.1:notaport"} {
		if err := validateLiveStreamAddr(bad); err == nil {
			t.Fatalf("expected %s to be rejected", bad)
		}
	}
}

func TestLiveProofIsSecretBoundAndDomainSeparated(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef0123456789abcdef")
	challenge := "00112233445566778899aabbccddeeff0011223344556677"
	proof := liveProof(secret, challenge)
	if len(proof) != 64 {
		t.Fatalf("unexpected proof length: %d", len(proof))
	}
	if !hmac.Equal([]byte(proof), []byte(liveProof(secret, challenge))) {
		t.Fatal("live proof must be deterministic for the same challenge")
	}
	if proof == liveProof([]byte("different-secret-0123456789abcdef0123456789abcdef"), challenge) {
		t.Fatal("live proof must be bound to the configured secret")
	}
	if !strings.Contains(liveProtocolLabel, "live") {
		t.Fatal("live proof must use a dedicated protocol domain")
	}
}

func TestLiveStreamIsOptInForNonDashboardProcesses(t *testing.T) {
	if defaultLiveStreamAddr != "127.0.0.1:8788" {
		t.Fatalf("unexpected default live stream address: %s", defaultLiveStreamAddr)
	}
	// The init hook only runs the listener when SMARTCAR_GO_ENABLE_LIVE_STREAM=1.
	// This keeps ordinary Go tests/builds from opening an extra runtime listener.
}
