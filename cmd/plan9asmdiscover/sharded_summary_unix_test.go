//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/llgo-compat/plan9asm/internal/ownedprocess"
)

func TestDiscoveryStatusActualCLI(t *testing.T) {
	const childKey = "PLAN9ASM_STATUS_TEST_LEDGER"
	if ledger := os.Getenv(childKey); ledger != "" {
		flag.CommandLine = flag.NewFlagSet("plan9asmdiscover", flag.ExitOnError)
		os.Args = []string{"plan9asmdiscover", "-status", "-out-dir", ledger,
			"-index-url", "http://127.0.0.1:1", "-proxy-url", "http://127.0.0.1:1"}
		if index := os.Getenv(childKey + "_INDEX"); index != "" {
			os.Args = []string{"plan9asmdiscover", "-scan-mode", "incremental", "-out-dir", ledger,
				"-index-url", index, "-proxy-url", index + "/proxy", "-workers", "1"}
		}
		main()
		os.Exit(0)
	}
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, discoveryReport{
		SchemaVersion: discoverySchema,
		IndexRanges:   []indexRange{{Since: indexEpoch, Before: "2026-10-07T00:00:00Z", IndexEntries: 1}},
		Scanned:       []moduleVersion{{Path: "example.com/a", Version: "v1.0.0"}},
	}); err != nil {
		t.Fatal(err)
	}
	complete, err := readShardedReport(ledger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDiscoveryStatusActualCLI$")
	command.Env = append(os.Environ(), childKey+"="+ledger)
	command.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := ownedprocess.Run(command); err != nil {
		t.Fatalf("actual -status failed: %v\n%s", err, stderr.String())
	}
	if ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatalf("actual -status has context/stderr failure: %v, %s", ctx.Err(), stderr.String())
	}
	var got ledgerSummary
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode actual -status: %v\n%s", err, stdout.String())
	}
	if want := summarizeLedger(complete); !reflect.DeepEqual(got, want) {
		t.Fatalf("actual CLI summary = %#v, want %#v", got, want)
	}

	// The last shard is outside the fixture's original data shard. Status must
	// consume it too, not stop after matching manifest counts in an earlier shard.
	if err := os.WriteFile(filepath.Join(ledger, "records", "ff.jsonl"), []byte("invalid tail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDiscoveryStatusActualCLI$")
	command.Env = append(os.Environ(), childKey+"="+ledger)
	command.WaitDelay = time.Second
	stdout.Reset()
	stderr.Reset()
	command.Stdout, command.Stderr = &stdout, &stderr
	err = ownedprocess.Run(command)
	var exit *exec.ExitError
	if ctx.Err() != nil || errors.Is(err, ownedprocess.ErrCleanup) || !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("actual invalid-tail status is not a plain failure: %v, context=%v, stderr=%s", err, ctx.Err(), stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), filepath.Join(ledger, "records", "ff.jsonl")+":1") ||
		!strings.Contains(stderr.String(), "decode record shard") {
		t.Fatalf("actual invalid tail lacks bound diagnostic/zero summary: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestDiscoveryPublishedReadbackActualCLI(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	anchor := "2026-10-01T00:00:00Z"
	if err := writeShardedReport(ledger, discoveryReport{
		SchemaVersion: discoverySchema,
		IndexRanges:   []indexRange{{Since: indexEpoch, Before: anchor, IndexEntries: 1}},
		Scanned:       []moduleVersion{{Path: "example.com/a", Version: "v1.0.0"}},
		Matched:       []candidate{{Module: "example.com/a", Version: "v1.0.0", AsmFiles: []string{"a_amd64.s"}}},
		Failures:      []scanFailure{{Module: "example.com/b", Version: "@latest", Error: "previous failure"}},
	}); err != nil {
		t.Fatal(err)
	}
	var requests, unexpected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/" || r.URL.Query().Get("since") != anchor {
			unexpected.Add(1)
			http.Error(w, "unexpected fixture request", http.StatusBadRequest)
			return
		}
		// A complete empty index page, not an external scan. No module proxy or
		// source inspection is required to publish the new zero-entry range.
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDiscoveryStatusActualCLI$")
	command.Env = append(os.Environ(), "PLAN9ASM_STATUS_TEST_LEDGER="+ledger, "PLAN9ASM_STATUS_TEST_LEDGER_INDEX="+server.URL)
	command.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := ownedprocess.Run(command); err != nil {
		t.Fatalf("actual publication/readback failed: %v\n%s", err, stderr.String())
	}
	if ctx.Err() != nil || stderr.Len() != 0 || requests.Load() != 1 || unexpected.Load() != 0 {
		t.Fatalf("publication context/stderr/request failure: %v, %s, %d/%d", ctx.Err(), stderr.String(), requests.Load(), unexpected.Load())
	}
	complete, err := readShardedReport(ledger)
	if err != nil {
		t.Fatal(err)
	}
	var got ledgerSummary
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("actual publication emitted invalid summary: %v\n%s", err, stdout.String())
	}
	if want := summarizeLedger(complete); !reflect.DeepEqual(got, want) {
		t.Fatalf("actual published summary = %#v, want full-reader view %#v", got, want)
	}
	if got.IndexRanges != 2 || got.HistoryBefore != indexEpoch || got.IncrementalSince == anchor ||
		got.IndexEntries != 1 || got.ScannedRecords != 1 || got.MatchedRecords != 1 || got.AssemblyFiles != 1 || got.FailureRecords != 1 {
		t.Fatalf("published range/record accounting = %#v", got)
	}
}
