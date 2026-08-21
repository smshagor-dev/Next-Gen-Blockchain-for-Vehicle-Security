package main

import (
	"os"
	"strings"
)

var runtimeAllowedSmartCarEnvironment = map[string]struct{}{
	"SMARTCAR_GO_API_SECRET":                    {},
	"SMARTCAR_GO_DATA_DIR":                      {},
	"SMARTCAR_GO_ALLOW_CLASSICAL_ECDH_FALLBACK": {},
	"SMARTCAR_IDENTITY_ADMISSION_POLICY":        {},
}

var runtimeBlockedInjectionEnvironment = map[string]struct{}{
	"PYTHONPATH":            {},
	"PYTHONHOME":            {},
	"LD_PRELOAD":            {},
	"LD_LIBRARY_PATH":       {},
	"DYLD_INSERT_LIBRARIES": {},
	"DYLD_LIBRARY_PATH":     {},
}

// sanitizeRuntimeEnvironment removes project credentials the Go backend does
// not need and common loader/interpreter injection variables. It intentionally
// preserves only the narrow SMARTCAR_* allow-list above.
func sanitizeRuntimeEnvironment() int {
	removed := 0
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		name := parts[0]
		if strings.HasPrefix(name, "SMARTCAR_") {
			if _, allowed := runtimeAllowedSmartCarEnvironment[name]; allowed {
				continue
			}
			if err := os.Unsetenv(name); err == nil {
				removed++
			}
			continue
		}
		if _, blocked := runtimeBlockedInjectionEnvironment[name]; blocked || strings.HasPrefix(name, "DYLD_") {
			if err := os.Unsetenv(name); err == nil {
				removed++
			}
		}
	}
	return removed
}

func init() {
	sanitizeRuntimeEnvironment()
}
