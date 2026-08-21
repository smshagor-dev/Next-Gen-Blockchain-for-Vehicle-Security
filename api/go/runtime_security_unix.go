//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import "syscall"

// Unix runtime hardening is intentionally limited to portable process-local
// controls: private file creation defaults and disabling core dumps.
func init() {
	syscall.Umask(0o077)
	limit := &syscall.Rlimit{Cur: 0, Max: 0}
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, limit)
}
