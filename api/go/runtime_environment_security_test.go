package main

import (
	"os"
	"testing"
)

func TestRuntimeEnvironmentRemovesUnneededSmartCarSecrets(t *testing.T) {
	t.Setenv("SMARTCAR_GO_API_SECRET", "A-secret-that-is-long-enough-for-runtime-test-123456")
	t.Setenv("SMARTCAR_GO_DATA_DIR", "/tmp/omniguard-runtime-test")
	t.Setenv("SMARTCAR_AUTH_TOKEN", "auth-secret-that-must-not-reach-go-runtime-123456")
	t.Setenv("SMARTCAR_VALIDATOR_KEY", "validator-secret-that-must-not-reach-go-123456")

	removed := sanitizeRuntimeEnvironment()
	if removed < 2 {
		t.Fatalf("expected at least two unrelated SMARTCAR variables removed, got %d", removed)
	}
	if os.Getenv("SMARTCAR_AUTH_TOKEN") != "" {
		t.Fatal("SMARTCAR_AUTH_TOKEN remained in Go runtime environment")
	}
	if os.Getenv("SMARTCAR_VALIDATOR_KEY") != "" {
		t.Fatal("SMARTCAR_VALIDATOR_KEY remained in Go runtime environment")
	}
	if os.Getenv("SMARTCAR_GO_API_SECRET") == "" {
		t.Fatal("required API secret was removed")
	}
	if os.Getenv("SMARTCAR_GO_DATA_DIR") == "" {
		t.Fatal("required data directory was removed")
	}
}

func TestRuntimeEnvironmentRemovesInjectionVariables(t *testing.T) {
	t.Setenv("PYTHONPATH", "/tmp/injected-python")
	t.Setenv("LD_PRELOAD", "/tmp/injected.so")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/injected.dylib")

	sanitizeRuntimeEnvironment()
	for _, name := range []string{"PYTHONPATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"} {
		if os.Getenv(name) != "" {
			t.Fatalf("%s remained in Go runtime environment", name)
		}
	}
}

func TestRuntimeEnvironmentKeepsExplicitNonSecretPolicy(t *testing.T) {
	t.Setenv("SMARTCAR_IDENTITY_ADMISSION_POLICY", "CERTIFICATE_AUTHORITY")
	t.Setenv("SMARTCAR_GO_ALLOW_CLASSICAL_ECDH_FALLBACK", "0")

	sanitizeRuntimeEnvironment()
	if os.Getenv("SMARTCAR_IDENTITY_ADMISSION_POLICY") != "CERTIFICATE_AUTHORITY" {
		t.Fatal("identity admission policy should remain available")
	}
	if os.Getenv("SMARTCAR_GO_ALLOW_CLASSICAL_ECDH_FALLBACK") != "0" {
		t.Fatal("ECDH fallback policy should remain available")
	}
}
