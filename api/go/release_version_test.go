package main

import (
	"os"
	"path/filepath"
	"regexp"
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
	if !regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).MatchString(releaseVersion) {
		t.Fatalf("release version is not canonical semantic version X.Y.Z: %q", releaseVersion)
	}
}
