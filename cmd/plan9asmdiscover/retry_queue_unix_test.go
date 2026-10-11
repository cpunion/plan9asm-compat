//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/llgo-compat/plan9asm/internal/ownedprocess"
)

func TestDiscoveryRetryActualCLI(t *testing.T) {
	const childKey = "PLAN9ASM_DISCOVERY_RETRY_ARGS"
	if encoded := os.Getenv(childKey); encoded != "" {
		var args []string
		if err := json.Unmarshal([]byte(encoded), &args); err != nil {
			t.Fatal(err)
		}
		flag.CommandLine = flag.NewFlagSet("plan9asmdiscover", flag.ExitOnError)
		os.Args = append([]string{"plan9asmdiscover"}, args...)
		main()
		os.Exit(0)
	}
	ledger := filepath.Join(t.TempDir(), "ledger")
	base := discoveryReport{
		IndexRanges: []indexRange{{Since: "2026-10-01T00:00:00Z", Before: "2026-10-02T00:00:00Z", IndexEntries: 9}},
		Failures: []scanFailure{
			{Module: "example.invalid/a", Version: "v1.0.0", Error: "owned persistent failure"},
			{Module: "example.invalid/b", Version: "v1.0.0", Error: "owned persistent failure"},
			{Module: "example.invalid/c", Version: "v1.0.0", Error: "owned persistent failure"},
		},
	}
	if err := writeShardedReport(ledger, base); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/@latest") {
			_, _ = w.Write([]byte(`{"Version":"v1.0.0"}`))
			return
		}
		// Keep the exact v1 failure line stable across batches. A failed latest
		// resolution would legitimately create an additional @latest line.
		http.Error(w, "owned persistent exact ZIP failure", http.StatusNotFound)
	}))
	defer server.Close()
	for batch := 0; batch < 6; batch++ {
		encoded, err := json.Marshal([]string{"-scan-mode", "retry", "-limit", "1", "-workers", "1", "-out-dir", ledger,
			"-index-url", server.URL + "/must-not-read-index", "-proxy-url", server.URL})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDiscoveryRetryActualCLI$")
		command.Env = append(os.Environ(), childKey+"="+string(encoded))
		command.WaitDelay = time.Second
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err = ownedprocess.Run(command)
		contextErr := ctx.Err()
		cancel()
		if err != nil || contextErr != nil {
			t.Fatalf("actual retry batch%d did not close successfully: %v context=%v stderr=%s", batch, err, contextErr, stderr.String())
		}
		var summary ledgerSummary
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("actual retry emitted invalid summary: %v\n%s", err, stdout.String())
		}
		mu.Lock()
		allRequests := append([]string(nil), requests...)
		requests = nil
		mu.Unlock()
		var got []string
		for _, request := range allRequests {
			if strings.HasSuffix(request, "/@latest") {
				got = append(got, request)
			} else if request != "/example.invalid/"+string(rune('a'+batch%3))+"/@v/v1.0.0.zip" {
				t.Fatalf("retry escaped its selected module: %v", allRequests)
			}
		}
		want := []string{"/example.invalid/" + string(rune('a'+batch%3)) + "/@latest"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("actual -limit1 retry batch%d exceeded or starved its bounded queue: requests=%v want=%v", batch, got, want)
		}
		if strings.Contains(stderr.String(), "must-not-read-index") || summary.IndexRanges != 1 || summary.IndexEntries != 9 ||
			summary.HistoryBefore != base.IndexRanges[0].Since || summary.IncrementalSince != base.IndexRanges[0].Before {
			t.Fatalf("retry changed index coverage: summary=%+v stderr=%s", summary, stderr.String())
		}
		persisted, err := scanShardedReport(ledger, nil)
		if err != nil || !reflect.DeepEqual(persisted.metadata.IndexRanges, base.IndexRanges) || persisted.metadata.IndexEntries != 9 {
			t.Fatalf("retry publication changed physical index ranges: %+v %v", persisted.metadata, err)
		}
		cursor := &moduleVersion{Path: "example.invalid/" + string(rune('a'+batch%3)), Version: "v1.0.0"}
		if !reflect.DeepEqual(persisted.metadata.RetryAfter, cursor) || !reflect.DeepEqual(summary.RetryAfter, cursor) {
			t.Fatalf("actual retry marker is not last input: summary=%+v manifest=%+v want=%+v", summary.RetryAfter, persisted.metadata.RetryAfter, cursor)
		}
	}
}

func runDiscoveryStreamingFixtureCLI(t *testing.T, args []string) ([]byte, []byte, error) {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDiscoveryRetryActualCLI$")
	command.Env = append(os.Environ(), "PLAN9ASM_DISCOVERY_RETRY_ARGS="+string(encoded))
	command.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = ownedprocess.Run(command)
	if ctx.Err() != nil {
		t.Fatalf("actual streaming CLI owner exceeded fixture budget: %v", ctx.Err())
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func TestDiscoveryStreamingNormalNewLedgerActualCLI(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "new-ledger")
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.URL.Path != "/" || r.URL.Query().Get("since") != indexEpoch {
			http.Error(w, "unexpected owned empty index request", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	before := "2019-04-10T00:00:01Z"
	stdout, stderr, err := runDiscoveryStreamingFixtureCLI(t, []string{"-scan-mode", "history", "-limit", "1", "-before", before,
		"-out-dir", ledger, "-index-url", server.URL, "-proxy-url", server.URL})
	if err != nil || len(stderr) != 0 {
		t.Fatalf("new empty ledger incorrectly became a missing seen input: %v %s", err, stderr)
	}
	var summary ledgerSummary
	if err := json.Unmarshal(stdout, &summary); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	count := requests
	mu.Unlock()
	if count != 1 || summary.HistoryBefore != indexEpoch || summary.IncrementalSince != before || summary.IndexEntries != 0 ||
		summary.ScannedRecords != 0 || summary.FailureRecords != 0 {
		t.Fatalf("actual empty new-ledger accounting: %+v requests=%d", summary, count)
	}
}

func TestDiscoveryRetryRejectsTailBeforeRequestsActualCLI(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, discoveryReport{Failures: []scanFailure{
		{Module: "example.invalid/a", Version: "v1.0.0", Error: "owned failure"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ledger, "records", "ff.jsonl"), []byte("invalid owned unselected tail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(ledger, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		http.Error(w, "must not reach owned proxy", http.StatusBadRequest)
	}))
	defer server.Close()
	_, stderr, err := runDiscoveryStreamingFixtureCLI(t, []string{"-scan-mode", "retry", "-limit", "1", "-out-dir", ledger,
		"-index-url", server.URL, "-proxy-url", server.URL})
	mu.Lock()
	count := requests
	mu.Unlock()
	if err == nil || count != 0 || !bytes.Contains(stderr, []byte("decode record shard")) {
		t.Fatalf("retry escaped full-ledger EOF validation: %v requests=%d %s", err, count, stderr)
	}
	after, err := os.ReadFile(filepath.Join(ledger, "manifest.json"))
	if err != nil || !bytes.Equal(after, manifest) {
		t.Fatalf("rejected input changed ledger manifest: %v", err)
	}
}
