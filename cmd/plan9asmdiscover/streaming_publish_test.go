package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryPublicationDoesNotRetainOldLedgerPayloads(t *testing.T) {
	const records = 8192
	ledger := writeSummaryPayloadFixture(t, records)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	stop := make(chan struct{})
	peak := make(chan uint64, 1)
	go func() {
		maximum := before.HeapAlloc
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			if stats.HeapAlloc > maximum {
				maximum = stats.HeapAlloc
			}
			select {
			case <-stop:
				peak <- maximum
				return
			case <-ticker.C:
			}
		}
	}()
	err := writeShardedReport(ledger, discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/new", Version: "v1.0.0"}},
	})
	close(stop)
	maximum := <-peak
	if err != nil {
		t.Fatal(err)
	}
	var growth uint64
	if maximum > before.HeapAlloc {
		growth = maximum - before.HeapAlloc
	}
	t.Logf("sampled HeapAlloc growth=%d bytes while publishing into %d records/%d payload bytes", growth, records, records*8192)
	if growth > 24<<20 {
		t.Errorf("publication retains old-ledger payloads: sampled HeapAlloc growth %d exceeds %d", growth, 24<<20)
	}
	summary, err := readShardedSummary(ledger)
	if err != nil || summary.ScannedRecords != 1 || summary.FailureRecords != records || summary.UniqueModules != records+1 {
		t.Fatalf("published summary=%+v: %v", summary, err)
	}
}

func TestDiscoveryStreamingPublicationMatchesReferenceMerge(t *testing.T) {
	base := discoveryReport{
		SchemaVersion: discoverySchema,
		GeneratedAt:   time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		IndexRanges:   []indexRange{{Since: "2025-10-01T00:00:00Z", Before: "2026-10-01T00:00:00Z", IndexEntries: 20}},
		Skipped:       2,
		Scanned: []moduleVersion{
			{Path: "example.com/a", Version: "v0.9.0"},
			{Path: "example.com/a", Version: "v1.9.0"},
			{Path: "example.com/a/v2", Version: "v2.0.0"},
		},
		Matched: []candidate{{Module: "example.com/a", Version: "v1.9.0", AsmFiles: []string{"a_arm64.s"}}},
		Failures: []scanFailure{
			{Module: "example.com/a", Version: "@latest", Error: "resolution unavailable"},
			{Module: "example.com/b", Version: "v1.0.0", Error: "old failure"},
			{Module: "example.com/c", Version: "@latest", Error: "still retryable"},
		},
	}
	updates := []discoveryReport{
		{
			SchemaVersion: discoverySchema,
			GeneratedAt:   base.GeneratedAt.Add(time.Hour),
			IndexRanges:   []indexRange{{Since: "2026-10-01T00:00:00Z", Before: "2026-10-02T00:00:00Z", IndexEntries: 10}},
			Skipped:       1,
			Scanned:       []moduleVersion{{Path: "example.com/a", Version: "v1.10.0"}},
			Matched:       []candidate{{Module: "example.com/a", Version: "v1.10.0", AsmFiles: []string{"a_amd64.s"}}},
			Failures: []scanFailure{
				{Module: "example.com/b", Version: "v1.0.0", Error: "first payload"},
				{Module: "example.com/b", Version: "v1.0.0", Error: "last payload wins"},
			},
		},
		{
			SchemaVersion: discoverySchema,
			Scanned:       []moduleVersion{{Path: "example.com/b", Version: "v1.1.0"}},
			Matched:       []candidate{{Module: "example.com/a", Version: "v1.10.0", AsmFiles: []string{"b_arm.s"}}},
		},
		{},
	}
	for _, update := range updates {
		ledger := filepath.Join(t.TempDir(), "ledger")
		if err := writeShardedReport(ledger, base); err != nil {
			t.Fatal(err)
		}
		want, err := mergeDiscoveryReports(base, update)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeShardedReport(ledger, update); err != nil {
			t.Fatal(err)
		}
		got, err := readShardedReport(ledger)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("streamed publication=%+v, want %+v: %v", got, want, err)
		}
	}
}

func TestDiscoveryStreamingPublicationRejectsCorruptUnchangedTail(t *testing.T) {
	ledger := writeSummaryPayloadFixture(t, 256)
	manifestPath := filepath.Join(ledger, "manifest.json")
	before, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := filepath.Glob(filepath.Join(ledger, "records", "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	last := shards[len(shards)-1]
	file, err := os.OpenFile(last, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("{corrupt unselected tail}\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("write=%v close=%v", writeErr, closeErr)
	}
	if err := writeShardedReport(ledger, discoveryReport{}); err == nil {
		t.Fatal("publication accepted corrupt unchanged tail")
	}
	after, err := os.ReadFile(manifestPath)
	if err != nil || string(before) != string(after) {
		t.Fatalf("failed publication changed authoritative manifest: %v", err)
	}
	data, err := os.ReadFile(last)
	if err != nil || !bytes.HasSuffix(data, []byte("{corrupt unselected tail}\n")) {
		t.Fatalf("failed publication modified the unchanged shard: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(ledger))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(ledger) {
		t.Fatalf("failed publication leaked a lock/staging directory: entries=%v err=%v", entries, err)
	}
}

func TestDiscoveryStreamingPublicationAcrossShardBoundaries(t *testing.T) {
	base := discoveryReport{SchemaVersion: discoverySchema}
	update := discoveryReport{SchemaVersion: discoverySchema}
	for i := 0; i < 768; i++ {
		module := fmt.Sprintf("example.com/sharded/%04d", i)
		switch i % 4 {
		case 0:
			base.Scanned = append(base.Scanned, moduleVersion{Path: module, Version: "v1.9.0"})
			update.Scanned = append(update.Scanned, moduleVersion{Path: module, Version: "v1.10.0"})
		case 1:
			base.Failures = append(base.Failures, scanFailure{Module: module, Version: "@latest", Error: "retry"})
			update.Matched = append(update.Matched, candidate{Module: module, Version: "v1.2.0", AsmFiles: []string{"a_amd64.s"}})
		case 2:
			base.Matched = append(base.Matched, candidate{Module: module, Version: "v0.8.0", AsmFiles: []string{"a_arm64.s"}})
			update.Failures = append(update.Failures, scanFailure{Module: module, Version: "v1.0.0", Error: "new major"})
		case 3:
			update.Scanned = append(update.Scanned, moduleVersion{Path: module, Version: "v1.0.0"})
		}
	}
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, base); err != nil {
		t.Fatal(err)
	}
	want, err := mergeDiscoveryReports(base, update)
	if err != nil {
		t.Fatal(err)
	}
	// No range is encoded when the reference merge's empty slice is omitted.
	// Compare with the public reader's decoded representation, not slice identity.
	if len(want.IndexRanges) == 0 {
		want.IndexRanges = nil
	}
	if err := writeShardedReport(ledger, update); err != nil {
		t.Fatal(err)
	}
	got, err := readShardedReport(ledger)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("shard-boundary publication differs from reference: %v", err)
	}
}

func TestDiscoveryPublicationBaseBindsInputGeneration(t *testing.T) {
	ledger := writeSummaryPayloadFixture(t, 128)
	base, err := openPublicationBase(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := base.verify(ledger); err != nil {
		t.Fatal(err)
	}
	shard := base.shards[len(base.shards)-1]
	file, err := os.OpenFile(shard, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("write=%v close=%v", writeErr, closeErr)
	}
	if err := base.verify(ledger); err == nil {
		t.Fatal("publication snapshot accepted an in-place generation change")
	}
}

func TestDiscoveryPublicationRestoresPreviousLedgerOnRenameFailure(t *testing.T) {
	root := t.TempDir()
	staging, destination := filepath.Join(root, "staging"), filepath.Join(root, "ledger")
	for name, data := range map[string]string{staging: "new", destination: "previous"} {
		if err := os.Mkdir(name, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(name, "data"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	failure := errors.New("injected publication rename failure")
	renamed := 0
	err := replacePublicationDirectory(staging, destination, true, func(from, to string) error {
		renamed++
		if renamed == 2 {
			return failure
		}
		return os.Rename(from, to)
	})
	if !errors.Is(err, failure) || renamed != 3 {
		t.Fatalf("publication error=%v, rename calls=%d", err, renamed)
	}
	data, err := os.ReadFile(filepath.Join(destination, "data"))
	if err != nil || string(data) != "previous" {
		t.Fatalf("publication lost previous authoritative ledger: %q, %v", data, err)
	}
}

func publicationModuleInShard(t *testing.T, shard byte) moduleVersion {
	t.Helper()
	for i := 0; i < 16384; i++ {
		module := fmt.Sprintf("example.com/shard-case/%02x/%04d", shard, i)
		if sha256.Sum256([]byte(module))[0] == shard {
			return moduleVersion{Path: module, Version: "v1.0.0"}
		}
	}
	t.Fatalf("no fixture module found for shard %02x", shard)
	return moduleVersion{}
}

func TestDiscoveryPublicationPreservesReadableUppercaseShardNames(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, discoveryReport{
		Scanned: []moduleVersion{publicationModuleInShard(t, 0xa0), publicationModuleInShard(t, 0xf0)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(ledger, "records", "f0.jsonl"), filepath.Join(ledger, "records", "F0.jsonl")); err != nil {
		t.Fatal(err)
	}
	want, err := readShardedReport(ledger)
	if err != nil {
		t.Fatalf("public reader rejects the preexisting fixture: %v", err)
	}
	if err := writeShardedReport(ledger, discoveryReport{}); err != nil {
		t.Fatalf("streaming publication rejects a readable unique uppercase shard: %v", err)
	}
	got, err := readShardedReport(ledger)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("uppercase shard publication changed records: %v", err)
	}
}

type publicationNamedShardEntry struct {
	os.DirEntry
	name string
}

func (e publicationNamedShardEntry) Name() string { return e.name }

func TestDiscoveryReaderRejectsDuplicateLogicalShardAliases(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, discoveryReport{Scanned: []moduleVersion{publicationModuleInShard(t, 0xa0)}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(ledger, "records"))
	if err != nil {
		t.Fatal(err)
	}
	// A case-insensitive host cannot create both physical aliases. Exercise the
	// actual shared reader's namespace validator with both directory entries;
	// this obligation runs on every host, without Skip or a copied validator.
	aliases := append(entries, publicationNamedShardEntry{DirEntry: entries[0], name: "A0.jsonl"})
	if _, err := recordShardPaths(ledger, aliases); err == nil || !strings.Contains(err.Error(), "duplicate logical record shard") {
		t.Fatalf("duplicate logical shard aliases were not rejected explicitly: %v", err)
	}
}
