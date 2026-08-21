package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseVersionMatchesRepositoryVersion(t *testing.T) {
	path := filepath.Join("..", "..", "VERSION")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canonical VERSION: %v", err)
	}
	want := strings.TrimSpace(string(raw))
	if releaseVersion != want {
		t.Fatalf("Go release version %q does not match VERSION %q", releaseVersion, want)
	}
	if releaseVersion != "3.0.2" {
		t.Fatalf("unexpected release version: %s", releaseVersion)
	}
}
