package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
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

func TestDiscoverySummaryDoesNotRetainRecordPayloads(t *testing.T) {
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
	summary, err := readShardedSummary(ledger)
	close(stop)
	maximum := <-peak
	if err != nil {
		t.Fatal(err)
	}
	if summary.FailureRecords != records || summary.ScannedRecords != 0 || summary.MatchedRecords != 0 {
		t.Fatalf("summary = %#v, want %d failures only", summary, records)
	}
	const budget = 24 << 20
	var growth uint64
	if maximum > before.HeapAlloc {
		growth = maximum - before.HeapAlloc
	}
	t.Logf("sampled HeapAlloc growth=%d bytes for %d records, %d payload bytes", growth, records, records*8192)
	if growth > budget {
		t.Fatalf("summary retains ledger-sized payloads: sampled HeapAlloc growth %d exceeds %d bytes", growth, budget)
	}
}

// Write one record at a time. The fixture itself does not keep the large input
// in Go memory, and shard order is independent of the implementation reader.
func writeSummaryPayloadFixture(t *testing.T, count int) string {
	t.Helper()
	ledger := t.TempDir()
	recordsDir := filepath.Join(ledger, "records")
	if err := os.Mkdir(recordsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := make(map[byte]*os.File)
	writers := make(map[byte]*bufio.Writer)
	t.Cleanup(func() {
		for _, file := range files {
			_ = file.Close()
		}
	})
	payload := strings.Repeat("p", 8192)
	for i := 0; i < count; i++ {
		module := fmt.Sprintf("example.com/payload/%08d", i)
		shard := sha256.Sum256([]byte(module))[0]
		if files[shard] == nil {
			file, err := os.Create(filepath.Join(recordsDir, fmt.Sprintf("%02x.jsonl", shard)))
			if err != nil {
				t.Fatal(err)
			}
			files[shard] = file
			writers[shard] = bufio.NewWriter(file)
		}
		item := shardedRecord{Kind: "failure", Module: module, Version: "v1.0.0", Error: payload}
		if err := json.NewEncoder(writers[shard]).Encode(item); err != nil {
			t.Fatal(err)
		}
	}
	for shard, writer := range writers {
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := files[shard].Close(); err != nil {
			t.Fatal(err)
		}
		delete(files, shard)
	}
	manifest := shardedManifest{
		SchemaVersion: discoverySchema, Format: shardedFormat,
		GeneratedAt:   time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC),
		UniqueModules: count, Failures: count, ShardKey: "sha256(module)[0]",
	}
	writeSummaryFixtureJSON(t, filepath.Join(ledger, "manifest.json"), manifest)
	return ledger
}

func writeSummaryFixtureJSON(t *testing.T, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverySummaryMatchesCompleteReader(t *testing.T) {
	report := discoveryReport{
		SchemaVersion: discoverySchema,
		IndexRanges: []indexRange{
			{Since: indexEpoch, Before: "2026-10-01T00:00:00Z", IndexEntries: 10},
			{Since: "2026-10-01T00:00:00Z", Before: "2026-10-07T00:00:00Z", IndexEntries: 20},
		},
		Scanned:  []moduleVersion{{Path: "example.com/a", Version: "v1.0.0"}, {Path: "example.com/a", Version: "v0.9.0"}},
		Matched:  []candidate{{Module: "example.com/a", Version: "v1.0.0", AsmFiles: []string{"a_amd64.s", "b_arm64.s"}}},
		Failures: []scanFailure{{Module: "example.com/b", Version: "@latest", Error: "unavailable"}},
	}
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, report); err != nil {
		t.Fatal(err)
	}
	complete, err := readShardedReport(ledger)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readShardedSummary(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if want := summarizeLedger(complete); !reflect.DeepEqual(got, want) {
		t.Fatalf("summary = %#v, want complete-reader view %#v", got, want)
	}
}

func TestDiscoveryStatusAndPublishedReadbackUseSummaryOnly(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var main *ast.FuncDecl
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "main" {
			main = function
		}
	}
	if main == nil {
		t.Fatal("main function is absent")
	}
	statusSummary := false
	for _, statement := range main.Body.List {
		conditional, ok := statement.(*ast.IfStmt)
		if !ok {
			continue
		}
		star, ok := conditional.Cond.(*ast.StarExpr)
		if !ok {
			continue
		}
		name, ok := star.X.(*ast.Ident)
		if !ok || name.Name != "statusOnly" {
			continue
		}
		ast.Inspect(conditional.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if function, ok := call.Fun.(*ast.Ident); ok && function.Name == "readShardedSummary" {
					statusSummary = true
				}
			}
			return true
		})
		break
	}
	if !statusSummary {
		t.Error("actual -status branch does not independently use readShardedSummary before full existing-ledger loading")
	}
	var publishedFullRead bool
	ast.Inspect(main.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) == 0 {
			return true
		}
		name, ok := assignment.Lhs[0].(*ast.Ident)
		if ok && name.Name == "persisted" {
			for _, expression := range assignment.Rhs {
				if call, ok := expression.(*ast.CallExpr); ok {
					if function, ok := call.Fun.(*ast.Ident); ok && function.Name == "readShardedReport" {
						publishedFullRead = true
					}
				}
			}
		}
		return true
	})
	if publishedFullRead {
		t.Error("actual publication readback retains complete record payloads instead of a validated summary")
	}
}

func TestDiscoverySummaryValidatesEveryRecordAndRange(t *testing.T) {
	base := shardedRecord{Kind: "scanned", Module: "example.com/a", Version: "v1.0.0"}
	for _, test := range []struct {
		name    string
		records []shardedRecord
		mutate  func(*shardedManifest)
		append  string
		want    string
	}{
		{name: "invalid final JSON", records: []shardedRecord{base}, append: "invalid tail\n", want: "decode record shard"},
		{name: "blank final line", records: []shardedRecord{base}, append: "\n", want: "decode record shard"},
		{name: "line budget", records: []shardedRecord{base}, append: strings.Repeat("x", 16<<20) + "\n", want: "token too long"},
		{name: "missing module", records: []shardedRecord{{Kind: "scanned", Version: "v1.0.0"}}, want: "incomplete module version"},
		{name: "missing version", records: []shardedRecord{{Kind: "scanned", Module: base.Module}}, want: "incomplete module version"},
		{name: "unknown kind", records: []shardedRecord{{Kind: "cgo", Module: base.Module, Version: base.Version}}, want: "unknown record kind"},
		{name: "invalid scanned version", records: []shardedRecord{{Kind: "scanned", Module: base.Module, Version: "@latest"}}, want: "invalid scanned module version"},
		{name: "invalid matched version", records: []shardedRecord{{Kind: "matched", Module: base.Module, Version: "invalid"}}, want: "invalid matched module version"},
		{name: "duplicate", records: []shardedRecord{base, base}, want: "duplicated or not in"},
		{name: "semver order", records: []shardedRecord{{Kind: "scanned", Module: base.Module, Version: "v1.10.0"}, base}, want: "duplicated or not in"},
		{name: "kind order", records: []shardedRecord{base, {Kind: "matched", Module: base.Module, Version: base.Version}}, want: "duplicated or not in"},
		{name: "scanned count", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.Scanned++ }, want: "record counts"},
		{name: "matched count", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.Matched++ }, want: "record counts"},
		{name: "failure count", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.Failures++ }, want: "record counts"},
		{name: "format", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.Format = "unknown" }, want: "unsupported format"},
		{name: "schema", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.SchemaVersion++ }, want: "unsupported schema"},
		{name: "shard key", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.ShardKey = "sha256(version)[0]" }, want: "unsupported shard key"},
		{name: "range total", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.IndexEntries++ }, want: "index range count"},
		{name: "range gap", records: []shardedRecord{base}, mutate: func(m *shardedManifest) {
			m.IndexRanges = append(m.IndexRanges, indexRange{Since: "2026-10-02T00:00:00Z", Before: "2026-10-03T00:00:00Z", IndexEntries: 0})
		}, want: "unverified gap"},
		{name: "range overlap", records: []shardedRecord{base}, mutate: func(m *shardedManifest) {
			m.IndexRanges = append(m.IndexRanges, indexRange{Since: "2026-09-01T00:00:00Z", Before: "2026-10-02T00:00:00Z", IndexEntries: 0})
		}, want: "overlap"},
		{name: "range negative", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.IndexRanges[0].IndexEntries = -1 }, want: "nonnegative"},
		{name: "range invalid time", records: []shardedRecord{base}, mutate: func(m *shardedManifest) { m.IndexRanges[0].Since = "invalid" }, want: "invalid index range"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ledger, shard := writeRawSummaryFixture(t, test.records, test.mutate)
			if test.append != "" {
				file, err := os.OpenFile(shard, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := file.WriteString(test.append)
				closeErr := file.Close()
				if err := errors.Join(writeErr, closeErr); err != nil {
					t.Fatal(err)
				}
			}
			for _, reader := range []struct {
				name string
				read func(string) error
			}{
				{"summary", func(name string) error { _, err := readShardedSummary(name); return err }},
				{"full", func(name string) error { _, err := readShardedReport(name); return err }},
			} {
				t.Run(reader.name, func(t *testing.T) {
					if err := reader.read(ledger); err == nil || !strings.Contains(err.Error(), test.want) {
						t.Fatalf("%s reader error = %v, want %q", reader.name, err, test.want)
					}
				})
			}
		})
	}
}

func writeRawSummaryFixture(t *testing.T, records []shardedRecord, mutate func(*shardedManifest)) (string, string) {
	t.Helper()
	ledger := t.TempDir()
	if err := os.Mkdir(filepath.Join(ledger, "records"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := shardedManifest{
		SchemaVersion: discoverySchema, Format: shardedFormat, ShardKey: "sha256(module)[0]",
		IndexRanges:  []indexRange{{Since: indexEpoch, Before: "2026-10-01T00:00:00Z", IndexEntries: 3}},
		IndexEntries: 3,
	}
	var buffer strings.Builder
	for _, record := range records {
		if err := json.NewEncoder(&buffer).Encode(record); err != nil {
			t.Fatal(err)
		}
		switch record.Kind {
		case "scanned":
			manifest.Scanned++
		case "matched":
			manifest.Matched++
		case "failure":
			manifest.Failures++
		}
	}
	if mutate != nil {
		mutate(&manifest)
	}
	writeSummaryFixtureJSON(t, filepath.Join(ledger, "manifest.json"), manifest)
	shard := filepath.Join(ledger, "records", fmt.Sprintf("%02x.jsonl", sha256.Sum256([]byte(records[0].Module))[0]))
	if err := os.WriteFile(shard, []byte(buffer.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return ledger, shard
}

func TestDiscoverySummaryRejectsShardAndGenerationChanges(t *testing.T) {
	base := shardedRecord{Kind: "scanned", Module: "example.com/a", Version: "v1.0.0"}
	for _, name := range []string{"wrong ownership", "directory", "invalid name", "missing records"} {
		t.Run(name, func(t *testing.T) {
			ledger, shard := writeRawSummaryFixture(t, []shardedRecord{base}, nil)
			switch name {
			case "wrong ownership":
				if err := os.Rename(shard, filepath.Join(ledger, "records", "00.jsonl")); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(filepath.Join(ledger, "records", "extra"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "invalid name":
				if err := os.WriteFile(filepath.Join(ledger, "records", "gg.jsonl"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing records":
				if err := os.Remove(shard); err != nil {
					t.Fatal(err)
				}
			}
			if summary, err := readShardedSummary(ledger); err == nil || summary != (ledgerSummary{}) {
				t.Fatalf("invalid shard input returned summary %#v, error=%v", summary, err)
			}
		})
	}
	for _, name := range []string{"manifest", "add shard", "replace shard", "edit shard", "replace directory"} {
		t.Run(name, func(t *testing.T) {
			ledger, shard := writeRawSummaryFixture(t, []shardedRecord{base}, nil)
			result, err := scanShardedReport(ledger, func(shardedRecord) error {
				switch name {
				case "manifest":
					file := filepath.Join(ledger, "manifest.json")
					data, err := os.ReadFile(file)
					if err != nil {
						return err
					}
					return os.WriteFile(file, append(data, '\n'), 0o600)
				case "add shard":
					return os.WriteFile(filepath.Join(ledger, "records", "ff.jsonl"), nil, 0o600)
				case "replace shard":
					data, err := os.ReadFile(shard)
					if err != nil {
						return err
					}
					if err := os.Rename(shard, shard+".saved"); err != nil {
						return err
					}
					// Keep the saved original outside the record directory.
					if err := os.Rename(shard+".saved", filepath.Join(ledger, "saved")); err != nil {
						return err
					}
					return os.WriteFile(shard, data, 0o600)
				case "edit shard":
					stamp := time.Now().Add(time.Hour)
					return os.Chtimes(shard, stamp, stamp)
				case "replace directory":
					manifest, err := os.ReadFile(filepath.Join(ledger, "manifest.json"))
					if err != nil {
						return err
					}
					data, err := os.ReadFile(shard)
					if err != nil {
						return err
					}
					if err := os.Rename(ledger, ledger+".saved"); err != nil {
						return err
					}
					t.Cleanup(func() { _ = os.RemoveAll(ledger + ".saved") })
					if err := os.MkdirAll(filepath.Join(ledger, "records"), 0o700); err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(ledger, "manifest.json"), manifest, 0o600); err != nil {
						return err
					}
					return os.WriteFile(shard, data, 0o600)
				}
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "input changed during validation") || !reflect.DeepEqual(result, shardedScan{}) {
				t.Fatalf("changed generation returned %#v, error=%v", result, err)
			}
		})
	}
}
