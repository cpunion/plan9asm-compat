package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDiscoveryGitMaintenanceCannotDetach(t *testing.T) {
	for _, key := range []string{"gc.autoDetach", "maintenance.autoDetach"} {
		command := exec.Command("git", "config", "--bool", "--get", key)
		command.Dir = t.TempDir()
		command.Env = discoveryCommandEnvironment(os.Environ())
		output, err := command.CombinedOutput()
		if err != nil || strings.TrimSpace(string(output)) != "false" {
			t.Errorf("%s = %q, %v; want foreground maintenance", key, output, err)
		}
	}
}

func TestDiscoveryCleanupRetriesOnlyTransientDirectoryRaces(t *testing.T) {
	for _, test := range []struct {
		name     string
		cause    error
		failures int
		wantRuns int
		wantErr  bool
	}{
		{"directory populated during unlink", syscall.ENOTEMPTY, 1, 2, false},
		{"persistent writer", syscall.ENOTEMPTY, 100, 3, true},
		{"permission denied", os.ErrPermission, 1, 1, true},
		{"other filesystem error", syscall.EIO, 1, 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			err := retryDiscoveryWorkspaceCleanup(3, 0, func() error {
				calls++
				if calls <= test.failures {
					return &os.PathError{Op: "unlinkat", Path: "candidate/module-cache/cache/vcs", Err: test.cause}
				}
				return nil
			})
			if calls != test.wantRuns || (err != nil) != test.wantErr {
				t.Fatalf("cleanup calls=%d err=%v, want calls=%d error=%v", calls, err, test.wantRuns, test.wantErr)
			}
			if test.wantErr && !errors.Is(err, test.cause) {
				t.Fatalf("lost cleanup failure: %v", err)
			}
		})
	}
}

func TestDiscoveryCleanupAlreadyRemoved(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "already-removed")
	if err := removeDiscoveryCandidateWorkspace(work); err != nil {
		t.Fatalf("already removed workspace: %v", err)
	}
	// Existing read-only directory coverage is in discovery_test.go. Keep
	// idempotency explicit because retries can encounter disappearing entries.
}
