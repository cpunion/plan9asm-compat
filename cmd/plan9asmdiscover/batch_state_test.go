package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryBatchStateRetainsOnlyActiveRecords(t *testing.T) {
	const records = 4096
	report := discoveryReport{SchemaVersion: discoverySchema}
	for i := 0; i < records; i++ {
		report.Scanned = append(report.Scanned, moduleVersion{
			Path: fmt.Sprintf("example.org/batch/%06d", i), Version: "v1.0.0",
		})
	}
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, report); err != nil {
		t.Fatal(err)
	}
	active := []moduleVersion{{Path: "example.org/batch/000042", Version: "v1.1.0"}}
	state, err := loadBatchState([]string{ledger}, active)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained seen=%d sourceSeen=%d checkpoints=%d for one active path, %d input records",
		len(state.seen), len(state.sourceSeen), len(state.checkpoints), records)
	if len(state.seen) != 1 || len(state.sourceSeen) != 0 || len(state.checkpoints) != 1 {
		t.Fatalf("retains ledger-sized maps: seen=%d sourceSeen=%d checkpoints=%d, want 1/0/1",
			len(state.seen), len(state.sourceSeen), len(state.checkpoints))
	}
	if _, ok := state.seen[scanKey(moduleVersion{Path: active[0].Path, Version: "v1.0.0"})]; !ok {
		t.Fatal("active exact-version checkpoint missing")
	}
}

func TestDiscoveryBatchStateMatchesCompleteReference(t *testing.T) {
	pseudo := "v0.0.0-20251001000000-0123456789ab"
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	for i, root := range []string{first, second} {
		report := discoveryReport{
			Scanned: []moduleVersion{
				{Path: "example.org/active", Version: "v0.9.0"},
				{Path: "example.org/active", Version: "v1.0.0"},
				{Path: "github.com/OWNER/Repo", Version: pseudo},
				{Path: "github.com/owner/repo/v2", Version: "v2.0.0"},
				{Path: "example.org/unselected", Version: "v1.0.0"},
			},
			Matched: []candidate{{
				Module: "github.com/OWNER/Repo", Version: pseudo,
				Architectures: []string{"obsolete"}, AsmFiles: []string{"z_arm64.s", "a_amd64.s"},
			}},
			Failures: []scanFailure{{Module: "example.org/active", Version: "@latest", Error: "retry"}},
		}
		if i == 1 {
			report.Matched[0].AsmFiles = []string{"b_386.s"}
		}
		if err := writeShardedReport(root, report); err != nil {
			t.Fatal(err)
		}
	}
	paths := []string{first, second, first}
	modules := []moduleVersion{
		{Path: "example.org/active", Version: "v1.1.0"},
		{Path: "github.com/owner/repo", Version: pseudo},
	}
	got, err := loadBatchState(paths, modules)
	if err != nil {
		t.Fatal(err)
	}
	want := batchReferenceState(t, []string{first, second}, []string{"example.org/active", "github.com/OWNER/Repo"})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered reference mismatch:\ngot %+v\nwant %+v", got, want)
	}
	if got.seen[scanKey(moduleVersion{Path: "example.org/active", Version: "@latest"})].Match.Module != "" {
		t.Fatal("retry failure became a successful inspection")
	}
	if _, ok := got.seen[scanKey(moduleVersion{Path: "example.org/active", Version: "@latest"})]; ok {
		t.Fatal("failure received exact completion credit")
	}
}

// The reference deliberately uses the original complete readers, then filters
// by an independently enumerated exact-path list, not the tested alias helper.
func batchReferenceState(t *testing.T, paths, retained []string) scanBatchState {
	t.Helper()
	seen, source, err := loadSeenState(paths)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints, err := loadModuleCheckpoints(paths)
	if err != nil {
		t.Fatal(err)
	}
	wanted := make(map[string]bool)
	for _, module := range retained {
		wanted[module] = true
	}
	for key := range seen {
		if !wanted[strings.Split(key, "\x00")[0]] {
			delete(seen, key)
		}
	}
	for key, item := range checkpoints {
		if !wanted[item.Path] {
			delete(checkpoints, key)
		}
	}
	keys := make(map[string]bool)
	for key := range seen {
		parts := strings.Split(key, "\x00")
		if alias := sourceScanKey(moduleVersion{Path: parts[0], Version: parts[1]}); alias != "" {
			keys[alias] = true
		}
	}
	for key := range source {
		if !keys[key] {
			delete(source, key)
		}
	}
	return scanBatchState{seen, source, checkpoints}
}

func TestDiscoveryBatchStateLegacyImportsAndCollections(t *testing.T) {
	report := discoveryReport{
		Scanned: []moduleVersion{
			{Path: "example.org/active", Version: "v1.0.0"},
			{Path: "example.org/other", Version: "v1.0.0"},
		},
		Matched:  []candidate{{Module: "example.org/active", Version: "v1.0.0", AsmFiles: []string{"old_amd64.s"}}},
		Failures: []scanFailure{{Module: "example.org/active", Version: "@latest", Error: "retry"}},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	plain, compressed := filepath.Join(t.TempDir(), "legacy.json"), filepath.Join(t.TempDir(), "legacy.json.gz")
	if err := os.WriteFile(plain, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(compressed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	writer := gzip.NewWriter(file)
	t.Cleanup(func() { _ = writer.Close() })
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plain, compressed} {
		state, err := loadBatchState([]string{path}, []moduleVersion{{Path: "example.org/active", Version: "v1.1.0"}})
		if err != nil || !reflect.DeepEqual(state, batchReferenceState(t, []string{path}, []string{"example.org/active"})) {
			t.Fatalf("legacy import %s: %+v, %v", path, state, err)
		}
	}

	collection := t.TempDir()
	for i, version := range []string{"v1.0.0", "v1.1.0"} {
		start, stop := fmt.Sprintf("2026-10-%02dT00:00:00Z", i+1), fmt.Sprintf("2026-10-%02dT00:00:00Z", i+2)
		root := filepath.Join(collection, fmt.Sprintf("run-%d", i))
		if err := writeShardedReport(root, discoveryReport{
			IndexRanges: []indexRange{{Since: start, Before: stop, IndexEntries: 1}},
			Scanned: []moduleVersion{
				{Path: "example.org/active", Version: version},
				{Path: "example.org/other", Version: version},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	state, err := loadBatchState([]string{collection}, []moduleVersion{{Path: "example.org/active", Version: "v1.2.0"}})
	if err != nil || !reflect.DeepEqual(state, batchReferenceState(t, []string{collection}, []string{"example.org/active"})) {
		t.Fatalf("collection import: %+v, %v", state, err)
	}
	if len(state.seen) != 1 || len(state.checkpoints) != 1 {
		t.Fatal("collection failed to retire the older line as the complete reference does")
	}
}

func TestDiscoveryBatchStateCollectionBoundaries(t *testing.T) {
	for _, name := range []string{"empty", "no-manifest", "symlink-only"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if name == "no-manifest" {
				if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if name == "symlink-only" {
				if err := os.Symlink(root, filepath.Join(root, "cycle")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadBatchState([]string{root}, nil); err == nil || !strings.Contains(err.Error(), "no manifest.json") {
				t.Fatalf("invalid collection accepted: %v", err)
			}
		})
	}
	t.Run("does-not-follow-child-symlink", func(t *testing.T) {
		root, outside := t.TempDir(), t.TempDir()
		if err := writeShardedReport(filepath.Join(root, "good"), discoveryReport{}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outside, "manifest.json"), []byte("invalid"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "foreign")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(root, filepath.Join(root, "cycle")); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBatchState([]string{root}, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unselected-source-range-gap", func(t *testing.T) {
		root := t.TempDir()
		for i, span := range [][2]string{{"2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"}, {"2026-10-03T00:00:00Z", "2026-10-04T00:00:00Z"}} {
			if err := writeShardedReport(filepath.Join(root, fmt.Sprint(i)), discoveryReport{
				IndexRanges: []indexRange{{Since: span[0], Before: span[1], IndexEntries: 1}},
			}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := loadBatchState([]string{root}, nil); err == nil {
			t.Fatal("range gap hidden by empty interest")
		}
		if _, err := readSeenReport(root); err == nil {
			t.Fatal("reference does not reject fixture's range gap")
		}
	})
}

func TestDiscoveryBatchStateRejectsAllUnselectedRecordKinds(t *testing.T) {
	for _, kind := range []string{"cgo", "latest", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			ledger := filepath.Join(t.TempDir(), "ledger")
			good := filepath.Join(t.TempDir(), "good")
			if err := writeShardedReport(good, discoveryReport{
				Scanned: []moduleVersion{{Path: "example.org/active", Version: "v1.0.0"}},
			}); err != nil {
				t.Fatal(err)
			}
			if err := writeShardedReport(ledger, discoveryReport{
				Scanned: []moduleVersion{{Path: "example.org/other", Version: "v1.0.0"}},
			}); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(filepath.Join(ledger, "records"))
			if err != nil || len(entries) != 1 {
				t.Fatalf("fixture shards: %v, %v", entries, err)
			}
			shard := filepath.Join(ledger, "records", entries[0].Name())
			writeSummaryFixtureJSON(t, shard, shardedRecord{Kind: kind, Module: "example.org/other", Version: "v1.0.0"})
			state, err := loadBatchState([]string{good, ledger}, []moduleVersion{{Path: "example.org/active", Version: "v1.0.0"}})
			if err == nil || !strings.Contains(err.Error(), "unknown record kind") || state.seen != nil || state.checkpoints != nil {
				t.Fatalf("unselected foreign kind retained state: %+v, %v", state, err)
			}
		})
	}
}

func TestDiscoveryBatchStateNormalSourceUsesStreamingScanner(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "batch_state.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			functions[fn.Name.Name] = fn
		}
	}
	calls := func(node ast.Node, wanted string) int {
		count := 0
		ast.Inspect(node, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == wanted {
					count++
				}
			}
			return true
		})
		return count
	}
	for _, name := range []string{"loadBatchState", "readBatchShardedReport"} {
		fn := functions[name]
		if fn == nil {
			t.Fatalf("missing consumer %s", name)
		}
		for _, full := range []string{"loadSeenState", "loadModuleCheckpoints", "readSeenReport", "readShardedReport", "readShardedReports"} {
			if calls(fn, full) != 0 {
				t.Fatalf("normal batch consumer %s uses full ledger reader %s", name, full)
			}
		}
	}
	if calls(functions["readBatchShardedReport"], "scanShardedReport") != 1 {
		t.Fatal("normal batch does not fully validate through the shared scanner")
	}
	fn := functions["readBatchSource"]
	if fn == nil || calls(fn, "readSeenReport") != 1 {
		t.Fatal("legacy compatibility source route changed")
	}
	allowed := 0
	for _, stmt := range fn.Body.List {
		branch, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		not, ok := branch.Cond.(*ast.UnaryExpr)
		if !ok || not.Op != token.NOT {
			continue
		}
		call, ok := not.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			continue
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "IsDir" {
			continue
		}
		if name, ok := selector.X.(*ast.Ident); ok && name.Name == "info" {
			allowed += calls(branch.Body, "readSeenReport")
		}
	}
	if allowed != 1 {
		t.Fatal("full legacy decoder is not limited to an explicit file source")
	}
}

func TestDiscoveryBatchStateGenerationCheckedAfterSelection(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, discoveryReport{Scanned: []moduleVersion{{Path: "example.org/active", Version: "v1.0.0"}}}); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(ledger, "manifest.json")
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	report, err := readBatchShardedReport(ledger, func(string) bool {
		if err := os.WriteFile(manifest, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return true
	})
	if err == nil || !strings.Contains(err.Error(), "input changed during validation") || len(report.Scanned) != 0 {
		t.Fatalf("provisional selected records escaped final guard: %+v, %v", report, err)
	}
}

func TestDiscoveryBatchPreparationLifecycle(t *testing.T) {
	modules := []moduleVersion{{Path: "example.org/active", Version: "v1.0.0"}}
	old := map[string]seenResult{"old": {}}
	want := scanBatchState{seen: map[string]seenResult{"active": {}}, sourceSeen: map[string]seenResult{}, checkpoints: map[string]moduleCheckpoint{}}
	for _, name := range []string{"nil-hook", "replace-copy", "load-error", "cancel-before", "cancel-after"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			cfg := config{seen: old}
			if name != "nil-hook" {
				cfg.loadState = func(input []moduleVersion) (scanBatchState, error) {
					calls++
					if !reflect.DeepEqual(input, modules) {
						t.Fatal("wrong active modules")
					}
					input[0].Path = "mutation-must-not-escape"
					if name == "load-error" {
						return scanBatchState{}, errors.New("fixture load error")
					}
					if name == "cancel-after" {
						cancel()
					}
					return want, nil
				}
			}
			if name == "cancel-before" {
				cancel()
			}
			got, err := prepareScanBatch(ctx, cfg, modules)
			if name == "load-error" || strings.HasPrefix(name, "cancel-") {
				if err == nil || got.seen != nil || got.sourceSeen != nil || got.checkpoints != nil {
					t.Fatalf("failed preparation yielded state: %+v %v", got, err)
				}
				if strings.HasPrefix(name, "cancel-") && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
			} else if name == "nil-hook" {
				if err != nil || !reflect.DeepEqual(got.seen, old) {
					t.Fatal("nil hook changed existing configuration")
				}
			} else if err != nil || !reflect.DeepEqual(got.seen, want.seen) || !reflect.DeepEqual(got.sourceSeen, want.sourceSeen) || !reflect.DeepEqual(got.checkpoints, want.checkpoints) {
				t.Fatalf("wrong replacement state: %+v %v", got, err)
			}
			if modules[0].Path != "example.org/active" || !reflect.DeepEqual(cfg.seen, old) {
				t.Fatal("caller-owned input/configuration mutated")
			}
			if (name == "cancel-before" || name == "nil-hook") && calls != 0 {
				t.Fatal("unexpected loader call")
			}
		})
	}
}

func TestDiscoveryBatchHookPrecedesCheckpointFiltering(t *testing.T) {
	entries := []indexEntry{
		{Path: "example.org/active", Version: "v1.0.0", Timestamp: time.Date(2019, 4, 10, 0, 0, 0, 0, time.UTC)},
		{Path: "example.org/active", Version: "v1.1.0", Timestamp: time.Date(2019, 4, 10, 0, 0, 0, 0, time.UTC)},
		{Path: "example.org/active", Version: "v0.9.0", Timestamp: time.Date(2019, 4, 10, 0, 0, 0, 0, time.UTC)},
	}
	proxyCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index" {
			for _, entry := range entries {
				_ = json.NewEncoder(w).Encode(entry)
			}
			return
		}
		proxyCalls++
		http.Error(w, "unexpected proxy call", http.StatusInternalServerError)
	}))
	defer server.Close()
	calls := 0
	cfg := config{
		indexURL: server.URL + "/index", proxyURL: server.URL, scanMode: scanModeHistory,
		before: "2019-04-10T00:00:01Z", after: indexEpoch, limit: 10, workers: 1, maxZipSize: 1 << 20,
		checkpoints: map[string]moduleCheckpoint{moduleLineKey("example.org/active", "v1.0.0"): {Path: "example.org/active", Version: "v99.0.0"}},
		loadState: func(modules []moduleVersion) (scanBatchState, error) {
			calls++
			want := []moduleVersion{{Path: "example.org/active", Version: "v0.9.0"}, {Path: "example.org/active", Version: "v1.1.0"}}
			if !reflect.DeepEqual(modules, want) {
				t.Fatalf("hook did not receive complete newest-per-major batch: %+v", modules)
			}
			checkpoints := make(map[string]moduleCheckpoint)
			for _, item := range modules {
				chooseModuleCheckpoint(checkpoints, item.Path, item.Version)
			}
			return scanBatchState{checkpoints: checkpoints}, nil
		},
	}
	report, err := discover(context.Background(), server.Client(), cfg)
	if err != nil || calls != 1 || report.UniqueModules != 2 || report.Skipped != 2 || len(report.Scanned) != 0 || len(report.Failures) != 0 || proxyCalls != 0 {
		t.Fatalf("incorrect batch route: calls=%d proxies=%d report=%+v error=%v", calls, proxyCalls, report, err)
	}
}

func TestDiscoveryBatchStatePreservesCaseAndVersionDomains(t *testing.T) {
	pseudo := "v0.0.0-20251001000000-0123456789ab"
	items := []moduleVersion{
		{Path: "github.com/OWNER/Repo", Version: pseudo},
		{Path: "github.com/owner/repo/v2", Version: "v2.0.0"},
		{Path: "github.com/owner/repo/Sub", Version: pseudo},
		{Path: "github.com/owner/repo/sub", Version: pseudo},
		{Path: "example.org/Repo", Version: "v0.9.0"},
		{Path: "example.org/Repo", Version: "v1.0.0"},
		{Path: "example.org/repo", Version: "v1.0.0"},
	}
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, discoveryReport{Scanned: items}); err != nil {
		t.Fatal(err)
	}
	state, err := loadBatchState([]string{ledger}, []moduleVersion{
		{Path: "github.com/owner/repo", Version: pseudo},
		{Path: "github.com/OWNER/REPO/Sub", Version: pseudo},
		{Path: "example.org/Repo", Version: "v1.1.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantSeen := make(map[string]seenResult)
	wantSource := make(map[string]seenResult)
	wantCheckpoints := make(map[string]moduleCheckpoint)
	for _, item := range []moduleVersion{items[0], items[2], items[4], items[5]} {
		rememberSeenResult(wantSeen, scanKey(item), seenResult{})
		rememberSeenResult(wantSource, sourceScanKey(item), seenResult{})
		chooseModuleCheckpoint(wantCheckpoints, item.Path, item.Version)
	}
	if !reflect.DeepEqual(state, scanBatchState{wantSeen, wantSource, wantCheckpoints}) {
		t.Fatalf("batch crosses case/submodule/major boundaries: %+v", state)
	}
}

func TestDiscoveryBatchStateEmptyInterestStillValidatesAllShards(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, discoveryReport{
		Scanned: []moduleVersion{{Path: "example.org/unselected", Version: "v1.0.0"}},
	}); err != nil {
		t.Fatal(err)
	}
	state, err := loadBatchState([]string{ledger}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.seen)+len(state.sourceSeen)+len(state.checkpoints) != 0 {
		t.Errorf("empty batch retains unrelated state: %+v", state)
	}
	entries, err := os.ReadDir(filepath.Join(ledger, "records"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("fixture inventory: %v %v", entries, err)
	}
	shard := filepath.Join(ledger, "records", entries[0].Name())
	file, err := os.OpenFile(shard, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("not-json\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = loadBatchState([]string{ledger}, nil)
	if err == nil || !strings.Contains(err.Error(), "decode record shard") ||
		state.seen != nil || state.sourceSeen != nil || state.checkpoints != nil {
		t.Fatalf("unselected invalid tail supplied state: %+v, %v", state, err)
	}
}
