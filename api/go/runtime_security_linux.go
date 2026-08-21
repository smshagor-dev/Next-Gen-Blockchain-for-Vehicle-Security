//go:build linux

package main

import "syscall"

const prSetNoNewPrivs = 38

// Linux no_new_privs prevents this process and its descendants from gaining
// privilege through execve-based mechanisms. Failure is non-fatal because the
// research prototype must still run on restricted kernels/containers, and the
// capability is reported as best-effort rather than certified isolation.
func init() {
	_, _, _ = syscall.RawSyscall6(
		syscall.SYS_PRCTL,
		uintptr(prSetNoNewPrivs),
		uintptr(1),
		0,
		0,
		0,
		0,
	)
}
