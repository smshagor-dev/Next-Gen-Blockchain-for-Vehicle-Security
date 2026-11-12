package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAtomicSaveReplacesFileAndPreservesPrivateMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "chain.json")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`[{"index":0,"event":"new"}]`)
	if err := atomicReplaceChainFile(target, payload); err != nil {
		t.Fatalf("atomic save: %v", err)
	}
	actual, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatalf("persisted wrong payload: %s", actual)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("unexpected saved chain mode %04o", info.Mode().Perm())
		}
	}
	assertNoChainTemps(t, dir)
}

func assertNoChainTemps(t *testing.T, dir string) {
	t.Helper()
	glob, err := filepath.Glob(filepath.Join(dir, ".chain-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(glob) != 0 {
		t.Fatalf("temporary chain files remain: %v", glob)
	}
}

func TestAtomicSaveRenameFailureNeverUnlinksPriorChain(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "chain.json")
	original := []byte("last valid snapshot")
	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected replace failure")
	calls := 0
	err := atomicReplaceChainFileWith(target, []byte("new state"), func(source, destination string) error {
		calls++
		if filepath.Dir(source) != dir || destination != target {
			t.Fatalf("unexpected temp/target paths %s %s", source, destination)
		}
		if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, original) {
			t.Fatalf("old chain already changed before replacement: %q %v", got, err)
		}
		return injected
	}, func(string) error {
		t.Fatal("directory fsync must not happen when replace fails")
		return nil
	})
	if !errors.Is(err, injected) || calls != 1 {
		t.Fatalf("rename must be attempted exactly once: calls=%d err=%v", calls, err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("failed rename lost the prior saved chain: %q %v", got, err)
	}
	assertNoChainTemps(t, dir)
}

func TestAtomicSaveDirectorySyncFailureReportsVisibleNewState(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "chain.json")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	uncertain := errors.New("injected parent sync failure")
	err := atomicReplaceChainFileWith(target, []byte("new state"), os.Rename, func(got string) error {
		if got != dir {
			t.Fatalf("wrong parent directory: %s", got)
		}
		return uncertain
	})
	if !errors.Is(err, uncertain) {
		t.Fatalf("directory fsync failure must be returned, got %v", err)
	}
	bytes, err := os.ReadFile(target)
	if err != nil || string(bytes) != "new state" {
		t.Fatalf("rename already happened before sync failure: %q %v", bytes, err)
	}
	assertNoChainTemps(t, dir)
}

func TestAtomicSaveInvalidArgumentsFailClosed(t *testing.T) {
	for _, input := range []struct {
		path string
		rename func(string, string) error
		sync func(string) error
	}{
		{"", os.Rename, syncChainParentDirectory},
		{"file", nil, syncChainParentDirectory},
		{"file", os.Rename, nil},
	} {
		if err := atomicReplaceChainFileWith(input.path, []byte("data"), input.rename, input.sync); err == nil {
			t.Fatalf("missing configuration rejection for %+v", input)
		}
	}
}

func TestAtomicSaveParentSyncOccursOnlyAfterReplacement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "chain.json")
	var replaced bool
	err := atomicReplaceChainFileWith(target, []byte("snapshot"), func(oldPath, targetPath string) error {
		contents, err := os.ReadFile(oldPath)
		if err != nil || string(contents) != "snapshot" {
			t.Fatalf("temp file has invalid data: %q %v", contents, err)
		}
		if err := os.Rename(oldPath, targetPath); err != nil {
			return err
		}
		replaced = true
		return nil
	}, func(path string) error {
		if !replaced || path != dir {
			t.Fatalf("directory sync occurred before rename or for wrong path")
		}
		return nil
	})
	if err != nil || !replaced {
		t.Fatalf("save/rename failed: %v", err)
	}
	assertNoChainTemps(t, dir)
}

func makeSaveRequest(t *testing.T, s *apiServer, nonce int) *http.Request {
	t.Helper()
	return signedRequest(
		t, s, http.MethodPost, "/save", []byte(`{}`),
		time.Now(), fmt.Sprintf("%032x", 30000+nonce),
	)
}

func TestAuthenticatedSavePersistsVerifiableSnapshot(t *testing.T) {
	server := testServer(t)
	initServer(t, server)
	req := makeSaveRequest(t, server, 1)
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("signed /save status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	server.state.mu.RLock()
	path := server.state.ChainFile
	expected := server.state.Chain
	server.state.mu.RUnlock()
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted []Block
	if err := json.Unmarshal(saved, &persisted); err != nil {
		t.Fatalf("invalid saved JSON: %v", err)
	}
	if len(persisted) != len(expected) || persisted[0].BlockHash != expected[0].BlockHash {
		t.Fatalf("persisted chain differs from verified in-memory snapshot")
	}
	if !strings.Contains(recorder.Body.String(), `"success":true`) {
		t.Fatalf("incorrect response %s", recorder.Body.String())
	}
}

func TestAuthenticatedSaveRejectsInvalidChainWithoutOverwritingFile(t *testing.T) {
	server := testServer(t)
	initServer(t, server)
	path := server.state.ChainFile
	if err := os.WriteFile(path, []byte("known good old checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	server.state.mu.Lock()
	server.state.Chain[0].BlockHash = "bad-hash"
	server.state.mu.Unlock()
	req := makeSaveRequest(t, server, 2)
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("invalid in-memory chain accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	still, err := os.ReadFile(path)
	if err != nil || string(still) != "known good old checkpoint" {
		t.Fatalf("invalid chain overwrote old data: %q %v", still, err)
	}
	assertNoChainTemps(t, filepath.Dir(path))
}

func TestConcurrentSignedSavesDoNotCorruptSnapshot(t *testing.T) {
	server := testServer(t)
	initServer(t, server)
	handler := server.routes()
	const workers = 12
	var wg sync.WaitGroup
	errorsCh := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			req := makeSaveRequest(t, server, 100+index)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				errorsCh <- fmt.Sprintf("save %d status=%d body=%s", index, recorder.Code, recorder.Body.String())
			}
		}(i)
	}
	wg.Wait()
	close(errorsCh)
	for failure := range errorsCh {
		t.Error(failure)
	}
	server.state.mu.RLock()
	path := server.state.ChainFile
	server.state.mu.RUnlock()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var blocks []Block
	if err := json.Unmarshal(raw, &blocks); err != nil {
		t.Fatalf("concurrent saving corrupted JSON: %v", err)
	}
	if len(blocks) != 1 || blocks[0].Index != 0 {
		t.Fatalf("bad saved genesis: %+v", blocks)
	}
	assertNoChainTemps(t, filepath.Dir(path))
}
