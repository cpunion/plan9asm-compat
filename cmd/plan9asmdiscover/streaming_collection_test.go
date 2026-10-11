package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryCollectionTransferMatchesOrderedReference(t *testing.T) {
	base := discoveryReport{
		GeneratedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		Failures:    []scanFailure{{Module: "example.com/a", Version: "@latest", Error: "destination unresolved"}},
		Scanned: []moduleVersion{
			{Path: "example.com/a", Version: "v1.9.0"},
			{Path: "example.com/a/v2", Version: "v2.0.0"},
			publicationModuleInShard(t, 0xa0),
		},
	}
	reports := []discoveryReport{
		{
			IndexRanges: []indexRange{{Since: "2026-10-01T00:00:00Z", Before: "2026-10-02T00:00:00Z", IndexEntries: 10}},
			Scanned:     []moduleVersion{{Path: "example.com/a", Version: "v1.10.0"}},
			Matched:     []candidate{{Module: "example.com/a", Version: "v1.10.0", Architectures: []string{"amd64"}, AsmFiles: []string{"a.s"}}},
			Failures: []scanFailure{
				{Module: "example.com/retry", Version: "v1.0.0", Error: "first"},
				{Module: "example.com/order", Version: "@latest", Error: "first unresolved"},
			},
			Skipped: 2,
		},
		{
			IndexRanges: []indexRange{{Since: "2026-10-02T00:00:00Z", Before: "2026-10-03T00:00:00Z", IndexEntries: 20}},
			Scanned:     []moduleVersion{{Path: "example.com/order", Version: "v1.0.0"}},
			Matched:     []candidate{{Module: "example.com/a", Version: "v1.10.0", Architectures: []string{"arm64"}, AsmFiles: []string{"b.s"}}},
			Failures:    []scanFailure{{Module: "example.com/retry", Version: "v1.0.0", Error: "second"}},
			RetryAfter:  &moduleVersion{Path: "example.com/retry", Version: "v1.0.0"},
			Skipped:     3,
		},
		{
			IndexRanges: []indexRange{{Since: "2026-10-03T00:00:00Z", Before: "2026-10-04T00:00:00Z", IndexEntries: 30}},
			Scanned:     []moduleVersion{publicationModuleInShard(t, 0xf0)},
			Failures: []scanFailure{
				{Module: "example.com/a", Version: "@latest", Error: "current unresolved"},
				{Module: "example.com/order", Version: "v0.9.0", Error: "older failure"},
				{Module: "example.com/order", Version: "@latest", Error: "later unresolved"},
				{Module: "example.com/retry", Version: "v1.0.0", Error: "last"},
			},
			Skipped: 4,
		},
	}
	for _, name := range []string{"new", "existing", "reversed", "source-alias", "uppercase-buckets"} {
		t.Run(name, func(t *testing.T) {
			ordered := append([]discoveryReport(nil), reports...)
			if name == "reversed" {
				ordered[0], ordered[2] = ordered[2], ordered[0]
			}
			source := writeTransferCollection(t, ordered)
			root := t.TempDir()
			destination, reference := filepath.Join(root, "destination"), filepath.Join(root, "reference")
			original := base
			if name == "new" {
				original = discoveryReport{}
			} else if err := writeShardedReport(destination, original); err != nil {
				t.Fatal(err)
			}
			if name == "uppercase-buckets" {
				for _, item := range []struct{ root, bucket string }{
					{filepath.Join(source, "run-002"), "f0"}, {destination, "a0"},
				} {
					if err := os.Rename(filepath.Join(item.root, "records", item.bucket+".jsonl"),
						filepath.Join(item.root, "records", strings.ToUpper(item.bucket)+".jsonl")); err != nil {
						t.Fatal(err)
					}
				}
			}
			// The existing whole reader defines collection order and aggregation.
			// It is a test reference only, never called by production transfer.
			change, err := readShardedReports(source)
			if err != nil {
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
			if name == "source-alias" {
				alias := filepath.Join(root, "alias")
				if err := os.Symlink(source, alias); err != nil {
					t.Fatal(err)
				}
				source = alias
			}
			if err := mergeLedgerStreaming(destination, source); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(readDirectoryFiles(t, destination), readDirectoryFiles(t, reference)) {
				t.Fatal("streamed collection differs from ordered complete reference")
			}
			canonical, err := filepath.EvalSymlinks(source)
			if err != nil || !reflect.DeepEqual(before, readDirectoryFiles(t, canonical)) {
				t.Fatalf("collection source changed: %v", err)
			}
		})
	}
}

func writeTransferCollection(t *testing.T, reports []discoveryReport) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "collection")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for i, report := range reports {
		if err := writeShardedReport(filepath.Join(root, fmt.Sprintf("run-%03d", i)), report); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDiscoveryCollectionTransferRejectsEveryInputThroughEOF(t *testing.T) {
	for _, name := range []string{"empty", "no-manifest", "symlink-cycle", "last-tail", "last-kind", "last-count", "range-gap"} {
		t.Run(name, func(t *testing.T) {
			reports := []discoveryReport{
				{IndexRanges: []indexRange{{Since: "2026-10-01T00:00:00Z", Before: "2026-10-02T00:00:00Z", IndexEntries: 1}},
					Scanned: []moduleVersion{{Path: "example.com/a", Version: "v1.0.0"}}},
				{IndexRanges: []indexRange{{Since: "2026-10-02T00:00:00Z", Before: "2026-10-03T00:00:00Z", IndexEntries: 1}},
					Scanned: []moduleVersion{publicationModuleInShard(t, 0xff)}},
			}
			if name == "empty" || name == "no-manifest" || name == "symlink-cycle" {
				reports = nil
			} else if name == "range-gap" {
				reports[1].IndexRanges[0].Since = "2026-10-03T00:00:00Z"
				reports[1].IndexRanges[0].Before = "2026-10-04T00:00:00Z"
			}
			source := writeTransferCollection(t, reports)
			last := filepath.Join(source, "run-001")
			switch name {
			case "no-manifest":
				if err := os.WriteFile(filepath.Join(source, "unrelated.json"), []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink-cycle":
				if err := os.Symlink(source, filepath.Join(source, "cycle")); err != nil {
					t.Fatal(err)
				}
			case "last-tail", "last-kind":
				path := filepath.Join(last, "records", "ff.jsonl")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if name == "last-tail" {
					data = append(data, []byte("invalid tail\n")...)
				} else {
					data = bytes.Replace(data, []byte(`"scanned"`), []byte(`"unknown"`), 1)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "last-count":
				path := filepath.Join(last, "manifest.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var manifest shardedManifest
				if err := json.Unmarshal(data, &manifest); err != nil {
					t.Fatal(err)
				}
				manifest.Scanned++
				writeSummaryFixtureJSON(t, path, manifest)
			}
			parent := t.TempDir()
			destination := filepath.Join(parent, "destination")
			if err := writeShardedReport(destination, discoveryReport{Scanned: []moduleVersion{{Path: "example.com/old", Version: "v1.0.0"}}}); err != nil {
				t.Fatal(err)
			}
			before := readDirectoryFiles(t, destination)
			if err := mergeLedgerStreaming(destination, source); err == nil {
				t.Fatal("incomplete collection was published")
			}
			if !reflect.DeepEqual(before, readDirectoryFiles(t, destination)) {
				t.Fatal("invalid last source changed authoritative destination")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 || entries[0].Name() != "destination" {
				t.Fatalf("failed collection leaked staging/locks: %v %v", entries, err)
			}
		})
	}
}

func TestDiscoveryCollectionTransferGenerationAndMembership(t *testing.T) {
	for _, name := range []string{"new-member", "deleted-member", "replaced-root", "replaced-member", "parent-alias", "member-alias", "new-root-manifest", "changed-member", "late-tail"} {
		t.Run(name, func(t *testing.T) {
			source := writeTransferCollection(t, []discoveryReport{{}, {}})
			sources, err := captureTransferSources(source)
			if err != nil {
				t.Fatal(err)
			}
			var inputs []*publicationBase
			for _, path := range sources.roots {
				input, err := openTransferInput(path)
				if err != nil {
					t.Fatal(err)
				}
				inputs = append(inputs, input)
			}
			switch name {
			case "new-member":
				if err := writeShardedReport(filepath.Join(source, "later"), discoveryReport{}); err != nil {
					t.Fatal(err)
				}
			case "deleted-member":
				if err := os.Remove(filepath.Join(source, "run-001", "manifest.json")); err != nil {
					t.Fatal(err)
				}
			case "replaced-root":
				if err := os.Rename(source, source+"-previous"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(source, 0o700); err != nil {
					t.Fatal(err)
				}
				for _, suffix := range []string{"run-000", "run-001"} {
					if err := writeShardedReport(filepath.Join(source, suffix), discoveryReport{}); err != nil {
						t.Fatal(err)
					}
				}
			case "replaced-member", "member-alias":
				path := filepath.Join(source, "run-001")
				if err := os.Rename(path, source+"-member-previous"); err != nil {
					t.Fatal(err)
				}
				if name == "member-alias" {
					replacement := filepath.Join(t.TempDir(), "replacement")
					if err := writeShardedReport(replacement, discoveryReport{}); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(replacement, path); err != nil {
						t.Fatal(err)
					}
				} else if err := writeShardedReport(path, discoveryReport{}); err != nil {
					t.Fatal(err)
				}
			case "parent-alias":
				if err := os.Rename(source, source+"-previous"); err != nil {
					t.Fatal(err)
				}
				replacement := writeTransferCollection(t, []discoveryReport{{}, {}})
				if err := os.Symlink(replacement, source); err != nil {
					t.Fatal(err)
				}
			case "new-root-manifest":
				data, err := os.ReadFile(filepath.Join(source, "run-000", "manifest.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, "manifest.json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "changed-member":
				path := filepath.Join(source, "run-001", "manifest.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			case "late-tail":
				if err := os.WriteFile(filepath.Join(source, "run-001", "records", "ff.jsonl"), []byte("invalid tail\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := verifyTransferGeneration(sources, inputs, "", nil); err == nil {
				t.Fatal("late source generation/membership change escaped final publication guard")
			}
		})
	}
}

func TestDiscoveryCollectionTransferDuplicateLogicalBucket(t *testing.T) {
	ledger := writeTransferCollection(t, []discoveryReport{{Scanned: []moduleVersion{publicationModuleInShard(t, 0xa0)}}})
	root := filepath.Join(ledger, "run-000")
	entries, err := os.ReadDir(filepath.Join(root, "records"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("bucket fixture: %v %v", entries, err)
	}
	// APFS may collapse the two spellings physically. The actual collection
	// scanner's independent namespace consumer must reject both on every host.
	entries = append(entries, publicationNamedShardEntry{DirEntry: entries[0], name: "A0.jsonl"})
	if _, err := recordShardPaths(root, entries); err == nil || !strings.Contains(err.Error(), "duplicate logical record shard") {
		t.Fatalf("collection duplicate logical bucket accepted: %v", err)
	}
}

func TestDiscoveryCollectionTransferNoFollowAndLocks(t *testing.T) {
	source := writeTransferCollection(t, []discoveryReport{{}, {}})
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "manifest.json"), []byte("not JSON\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bad, filepath.Join(source, "ignored-directory")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, filepath.Join(source, "ignored-cycle")); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "destination")
	if err := mergeLedgerStreaming(destination, source); err != nil {
		t.Fatalf("collection followed symlink directories/cycle: %v", err)
	}
	for _, lock := range []string{source, filepath.Join(source, "run-000"), filepath.Join(source, "run-001"), destination} {
		release, err := acquireLedgerLock(lock)
		if err != nil {
			t.Fatal(err)
		}
		err = mergeLedgerStreaming(destination, source)
		if releaseErr := release(); releaseErr != nil {
			t.Fatal(releaseErr)
		}
		if err == nil || !strings.Contains(err.Error(), "another discovery writer") {
			t.Fatalf("collection did not respect held source/member/destination lock: %v", err)
		}
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{source, filepath.Dir(source), filepath.Join(source, "new"), filepath.Join(source, "run-001"), alias, filepath.Join(alias, "nested")} {
		if err := mergeLedgerStreaming(destination, source); err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("collection physical alias/ancestor accepted: %s: %v", destination, err)
		}
	}
}

func TestDiscoveryCollectionTransferCursorEarlyErrors(t *testing.T) {
	for _, name := range []string{"receiver-error", "late-decoder-error"} {
		t.Run(name, func(t *testing.T) {
			ledger := writeSummaryPayloadFixture(t, 128)
			entries, err := os.ReadDir(filepath.Join(ledger, "records"))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(ledger, "records", entries[0].Name())
			var cursors []*transferModuleCursor
			for i := 0; i < 4; i++ {
				cursor, err := newTransferModuleCursor(path)
				if err != nil {
					t.Fatal(err)
				}
				cursors = append(cursors, cursor)
			}
			if name == "late-decoder-error" {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(data, []byte("invalid tail\n")...), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := transferCursorModules(&publicationShardWriter{root: filepath.Join(t.TempDir(), "missing")}, cursors); err == nil {
				t.Fatal("collection receiver/decoder error disappeared")
			}
		})
	}
}

func TestDiscoveryCollectionTransferCLIDirectoryCannotUseLegacyReader(t *testing.T) {
	assertDiscoveryDirectoryTransferRoute(t)
}

func assertDiscoveryDirectoryTransferRoute(t *testing.T) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	registered := 0
	ast.Inspect(file, func(node ast.Node) bool {
		branch, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		isDirectory, isConversion := false, false
		ast.Inspect(branch.Cond, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "IsDir" {
					isDirectory = true
				}
			}
			return true
		})
		if branch.Init != nil {
			ast.Inspect(branch.Init, func(node ast.Node) bool {
				if name, ok := node.(*ast.Ident); ok && name.Name == "convertReport" {
					isConversion = true
				}
				return true
			})
		}
		if !isDirectory || !isConversion {
			return true
		}
		streamCalls := 0
		ast.Inspect(branch.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok {
					if name.Name == "mergeLedgerStreaming" {
						streamCalls++
					}
					if name.Name == "readSeenReport" || name.Name == "readShardedReports" {
						t.Errorf("directory conversion calls full reader %s", name.Name)
					}
				}
			}
			return true
		})
		if _, ok := branch.Body.List[len(branch.Body.List)-1].(*ast.ReturnStmt); !ok {
			t.Error("collection directory falls through to legacy full reader")
		}
		if streamCalls != 1 {
			t.Errorf("directory has %d streaming calls, want one mandatory call", streamCalls)
		}
		registered++
		return true
	})
	if registered != 1 {
		t.Fatalf("actual CLI has %d directory conversion branches, want one", registered)
	}
}
