package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryTransferDoesNotRetainEitherLedgerPayloads(t *testing.T) {
	const records = 8192
	source, destination := writeSummaryPayloadFixture(t, records), writeSummaryPayloadFixture(t, records)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	stop, peak := make(chan struct{}), make(chan uint64, 1)
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
	err := mergeLedgerStreaming(destination, source)
	close(stop)
	maximum := <-peak
	if err != nil {
		t.Fatal(err)
	}
	var growth uint64
	if maximum > before.HeapAlloc {
		growth = maximum - before.HeapAlloc
	}
	t.Logf("sampled HeapAlloc growth=%d bytes importing %d source + %d destination records, each %d payload bytes",
		growth, records, records, records*8192)
	if growth > 24<<20 {
		t.Errorf("conversion retains ledger payloads: sampled HeapAlloc growth %d exceeds %d", growth, 24<<20)
	}
	summary, err := readShardedSummary(destination)
	if err != nil || summary.FailureRecords != records || summary.UniqueModules != records {
		t.Fatalf("transfer summary=%+v: %v", summary, err)
	}
}

func TestDiscoveryTransferMatchesWholeReference(t *testing.T) {
	base := discoveryReport{
		GeneratedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		IndexRanges: []indexRange{{Since: "2026-10-01T00:00:00Z", Before: "2026-10-02T00:00:00Z", IndexEntries: 10}},
		Skipped:     2, RetryAfter: &moduleVersion{Path: "example.com/retry", Version: "v1.0.0"},
		Scanned: []moduleVersion{{Path: "example.com/a", Version: "v0.9.0"}, {Path: "example.com/a", Version: "v1.9.0"}},
		Matched: []candidate{{Module: "example.com/a", Version: "v1.9.0", AsmFiles: []string{"a_arm64.s"}}},
		Failures: []scanFailure{
			{Module: "example.com/a", Version: "@latest", Error: "resolve"},
			{Module: "example.com/retry", Version: "v1.0.0", Error: "old"},
		},
	}
	update := discoveryReport{
		GeneratedAt: base.GeneratedAt.Add(time.Hour),
		IndexRanges: []indexRange{{Since: "2026-10-02T00:00:00Z", Before: "2026-10-03T00:00:00Z", IndexEntries: 20}},
		Skipped:     3, RetryAfter: &moduleVersion{Path: "example.com/retry", Version: "v1.1.0"},
		Scanned:  []moduleVersion{{Path: "example.com/a", Version: "v1.10.0"}, {Path: "example.com/a/v2", Version: "v2.0.0"}},
		Matched:  []candidate{{Module: "example.com/a", Version: "v1.10.0", AsmFiles: []string{"a_amd64.s"}}},
		Failures: []scanFailure{{Module: "example.com/retry", Version: "v1.0.0", Error: "replacement failure"}},
	}
	for i := 0; i < 512; i++ {
		module := fmt.Sprintf("example.com/transfer/%04d", i)
		base.Scanned = append(base.Scanned, moduleVersion{Path: module, Version: "v1.0.0"})
		update.Failures = append(update.Failures, scanFailure{Module: module, Version: "v1.1.0", Error: "retry"})
	}
	for _, name := range []string{"existing", "new", "empty-source"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source, destination, reference := filepath.Join(root, "source"), filepath.Join(root, "destination"), filepath.Join(root, "reference")
			original, change := base, update
			if name == "new" {
				original = discoveryReport{}
			} else if name == "empty-source" {
				change = discoveryReport{}
			}
			if name != "new" {
				if err := writeShardedReport(destination, original); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeShardedReport(source, change); err != nil {
				t.Fatal(err)
			}
			want, err := mergeDiscoveryReports(original, change)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeShardedReport(reference, want); err != nil {
				t.Fatal(err)
			}
			before := readDirectoryFiles(t, source)
			if err := mergeLedgerStreaming(destination, source); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(readDirectoryFiles(t, destination), readDirectoryFiles(t, reference)) {
				t.Fatal("streamed import differs from complete canonical reference")
			}
			if !reflect.DeepEqual(before, readDirectoryFiles(t, source)) {
				t.Fatal("transfer changed source")
			}
		})
	}
}

func TestDiscoveryTransferLogicalUppercaseBuckets(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	for _, name := range []string{source, destination} {
		if err := writeShardedReport(name, discoveryReport{Scanned: []moduleVersion{
			publicationModuleInShard(t, 0xa0), publicationModuleInShard(t, 0xf0),
		}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []struct{ root, old, changed string }{
		{source, "f0.jsonl", "F0.jsonl"}, {destination, "a0.jsonl", "A0.jsonl"},
	} {
		if err := os.Rename(filepath.Join(entry.root, "records", entry.old), filepath.Join(entry.root, "records", entry.changed)); err != nil {
			t.Fatal(err)
		}
	}
	want, err := readShardedReport(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := mergeLedgerStreaming(destination, source); err != nil {
		t.Fatal(err)
	}
	got, err := readShardedReport(destination)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("logical bucket traversal changed records: %v", err)
	}
}

func TestDiscoveryTransferRejectsCorruptInputsWithoutPublication(t *testing.T) {
	for _, name := range []string{"source-tail", "destination-tail", "unknown-kind", "counts", "range-gap"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
			for _, ledger := range []string{source, destination} {
				if err := writeShardedReport(ledger, discoveryReport{
					IndexRanges: []indexRange{{Since: "2026-10-01T00:00:00Z", Before: "2026-10-02T00:00:00Z", IndexEntries: 1}},
					Scanned:     []moduleVersion{{Path: "example.com/a", Version: "v1.0.0"}},
				}); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "source-tail", "destination-tail", "unknown-kind":
				ledger, payload := source, []byte("invalid tail\n")
				if name == "destination-tail" {
					ledger = destination
				} else if name == "unknown-kind" {
					item := publicationModuleInShard(t, 0xff)
					payload = []byte(fmt.Sprintf("{\"kind\":\"cgo\",\"module\":%q,\"version\":%q}\n", item.Path, item.Version))
				}
				if err := os.WriteFile(filepath.Join(ledger, "records", "ff.jsonl"), payload, 0o600); err != nil {
					t.Fatal(err)
				}
			case "counts", "range-gap":
				manifestPath := filepath.Join(source, "manifest.json")
				data, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				if name == "counts" {
					data = bytes.Replace(data, []byte(`"scanned_records": 1`), []byte(`"scanned_records": 2`), 1)
				} else {
					data = bytes.ReplaceAll(data, []byte("2026-10-01"), []byte("2026-10-03"))
					data = bytes.ReplaceAll(data, []byte("2026-10-02"), []byte("2026-10-04"))
				}
				if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := readDirectoryFiles(t, destination)
			if err := mergeLedgerStreaming(destination, source); err == nil {
				t.Fatal("invalid complete input was published")
			}
			if !reflect.DeepEqual(before, readDirectoryFiles(t, destination)) {
				t.Fatal("failed transfer changed authoritative destination")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 2 {
				t.Fatalf("transfer leaked staging/locks: %v %v", entries, err)
			}
		})
	}
}

func TestDiscoveryTransferLocksAndPhysicalOverlap(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	for _, name := range []string{source, destination} {
		if err := writeShardedReport(name, discoveryReport{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{source, destination} {
		release, err := acquireLedgerLock(name)
		if err != nil {
			t.Fatal(err)
		}
		err = mergeLedgerStreaming(destination, source)
		if releaseErr := release(); releaseErr != nil {
			t.Fatal(releaseErr)
		}
		if err == nil || !strings.Contains(err.Error(), "another discovery writer") {
			t.Fatalf("transfer failed to respect held input/output lock: %v", err)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{source, root, filepath.Join(source, "new", "nested"), alias, filepath.Join(alias, "new")} {
		if err := mergeLedgerStreaming(dest, source); err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("physical same/ancestor source alias allowed: %q %v", dest, err)
		}
	}
	// A case-sensitive host has no physical uppercase alias. Check its actual
	// identity when present, without inventing one or weakening the other axes.
	upper := filepath.Join(root, "SOURCE")
	if info, err := os.Stat(upper); err == nil {
		original, err := os.Stat(source)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(info, original) {
			if _, _, err := streamingTransferPaths(source, upper); err == nil || !strings.Contains(err.Error(), "overlap") {
				t.Fatalf("physical case alias allowed: %v", err)
			}
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestDiscoveryTransferIteratorJoinsOnEveryEarlyError(t *testing.T) {
	for _, name := range []string{"blocked-cancel", "receiver-error", "decoder-error"} {
		t.Run(name, func(t *testing.T) {
			ledger := writeSummaryPayloadFixture(t, 128)
			entries, err := os.ReadDir(filepath.Join(ledger, "records"))
			if err != nil {
				t.Fatal(err)
			}
			shard := filepath.Join(ledger, "records", entries[0].Name())
			if name == "decoder-error" {
				if err := os.WriteFile(shard, []byte("invalid tail\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			old, change := newTransferModuleIterator(shard), newTransferModuleIterator(shard)
			if name == "blocked-cancel" {
				old.close()
				change.close()
			} else if err := transferModuleStreams(&publicationShardWriter{root: filepath.Join(t.TempDir(), "missing")}, old, change); err == nil {
				t.Fatal("receiver/decoder failure disappeared")
			}
			for _, stream := range []*transferModuleIterator{old, change} {
				select {
				case <-stream.done:
				default:
					t.Fatal("early error returned before reader join")
				}
			}
		})
	}
}

func TestDiscoveryTransferSnapshotDetectsLateInputChange(t *testing.T) {
	for _, changed := range []string{"manifest", "record", "directory"} {
		t.Run(changed, func(t *testing.T) {
			ledger := writeSummaryPayloadFixture(t, 8)
			base, err := openTransferInput(ledger)
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(ledger, "manifest.json")
			if changed == "record" {
				name = base.shards[0]
			} else if changed == "directory" {
				if err := os.Rename(ledger, ledger+"-previous"); err != nil {
					t.Fatal(err)
				}
				if err := writeShardedReport(ledger, discoveryReport{}); err != nil {
					t.Fatal(err)
				}
			}
			if changed != "directory" {
				data, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, append(data, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := base.verify(ledger); err == nil || !strings.Contains(err.Error(), "input changed") {
				t.Fatalf("late snapshot mutation escaped: %v", err)
			}
		})
	}
}

func TestDiscoveryTransferNeverCallsWholePayloadReaders(t *testing.T) {
	for _, filename := range []string{"streaming_transfer.go", "streaming_collection.go", "streaming_transfer_cursor.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok {
					for _, forbidden := range []string{"readSeenReport", "readShardedReport", "readShardedReports", "loadSeenState", "loadModuleCheckpoints"} {
						if name.Name == forbidden {
							t.Errorf("transfer uses full payload reader %s in %s", name.Name, filename)
						}
					}
				}
			}
			return true
		})
	}
}

func TestDiscoveryTransferShardedCLIRouteReturnsBeforeLegacyRead(t *testing.T) {
	assertDiscoveryDirectoryTransferRoute(t)
}
