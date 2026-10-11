//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Model Go exiting while a Git subprocess still owns its private cache.
// Detached stdio also exercises descendants that Cmd.Wait cannot observe.
func TestDiscoveryCommandStopsCacheWriters(t *testing.T) {
	const helperEnv = "PLAN9ASM_TEST_CACHE_WRITER"
	if mode := os.Getenv(helperEnv); mode != "" {
		runDiscoveryCacheWriterHelper(t, helperEnv, mode)
		return
	}

	for _, mode := range []string{"success", "failure", "cancel", "cancel-with-pipe"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			ready := filepath.Join(dir, "ready")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			env := replaceEnv(os.Environ(), map[string]string{helperEnv: mode})
			done := make(chan error, 1)
			go func() {
				_, err := runCapturedCommandOutput(ctx, dir, env, os.Args[0], "-test.run=^TestDiscoveryCommandStopsCacheWriters$")
				done <- err
			}()
			pid := waitDiscoveryCacheWriter(t, ready)
			t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
			if strings.HasPrefix(mode, "cancel") {
				cancel()
			}
			select {
			case err := <-done:
				if mode == "success" && err != nil {
					t.Fatalf("successful command: %v", err)
				}
				if mode == "failure" {
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) || exitErr.ExitCode() != 17 {
						t.Fatalf("lost command failure: %v", err)
					}
				}
				if strings.HasPrefix(mode, "cancel") && !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("command cancellation left a descendant holding the output pipe")
			}

			// Release the descendant only after command completion. A surviving
			// process can now recreate cache files while the caller removes them.
			writeTestFile(t, filepath.Join(dir, "release"), "")
			time.Sleep(150 * time.Millisecond)
			if _, err := os.Stat(filepath.Join(dir, "late-write")); !os.IsNotExist(err) {
				t.Fatalf("descendant wrote cache after command returned: %v", err)
			}
		})
	}
}

func waitDiscoveryCacheWriter(t *testing.T, ready string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(ready); err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				return pid
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cache writer did not start")
	return 0
}

func runDiscoveryCacheWriterHelper(t *testing.T, helperEnv, mode string) {
	t.Helper()
	if mode == "writer" {
		writeTestFile(t, "ready", strconv.Itoa(os.Getpid()))
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat("release"); err == nil {
				writeTestFile(t, "late-write", "cache changed")
				os.Exit(0)
			}
			time.Sleep(5 * time.Millisecond)
		}
		os.Exit(0)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestDiscoveryCommandStopsCacheWriters$")
	child.Env = replaceEnv(os.Environ(), map[string]string{helperEnv: "writer"})
	if mode == "cancel-with-pipe" {
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waitDiscoveryCacheWriter(t, "ready")
	if strings.HasPrefix(mode, "cancel") {
		time.Sleep(5 * time.Second)
	}
	if mode == "failure" {
		os.Exit(17)
	}
	os.Exit(0)
}
