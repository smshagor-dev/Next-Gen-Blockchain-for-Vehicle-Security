package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// atomicReplaceChainFile saves a manually requested snapshot. It is intentionally
// not a transaction log: blocks added after the snapshot still require another
// /save request. It does not authenticate chain receipts or prevent host rollback.
func atomicReplaceChainFile(target string, payload []byte) error {
	return atomicReplaceChainFileWith(target, payload, os.Rename, syncChainParentDirectory)
}

// Injectable filesystem actions permit testing failure boundaries without
// making a real existing ledger file or any vehicle state expendable.
func atomicReplaceChainFileWith(
	target string,
	payload []byte,
	replace func(oldPath, newPath string) error,
	syncParent func(directory string) error,
) error {
	if target == "" || replace == nil || syncParent == nil {
		return fmt.Errorf("invalid chain persistence configuration")
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create chain directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".chain-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary chain file: %w", err)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()

	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure temporary chain file: %w", err)
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write chain snapshot: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary chain file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary chain file: %w", err)
	}
	// Never remove the existing destination as a fallback. A rename failure
	// leaves the previously saved chain intact, and only the temp is removed.
	if err := replace(tempName, target); err != nil {
		return fmt.Errorf("replace chain snapshot: %w", err)
	}
	// A directory sync failure occurs AFTER rename. The replacement may
	// already be visible; report uncertainty rather than claiming rollback.
	if err := syncParent(dir); err != nil {
		return fmt.Errorf("sync chain directory after replacement: %w", err)
	}
	return nil
}

func syncChainParentDirectory(dir string) error {
	// Portable Go cannot fsync directories on Windows. A successful save
	// there only confirms the file sync plus OS atomic rename semantics.
	if runtime.GOOS == "windows" {
		return nil
	}
	fd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer fd.Close()
	return fd.Sync()
}
