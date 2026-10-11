package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiscoveryRetryInputBoundaryAndEmptyClear(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ledger")
	base := discoveryReport{Failures: []scanFailure{
		{Module: "example.invalid/a", Version: "v1.0.0", Error: "owned failure"},
		{Module: "example.invalid/b", Version: "v1.0.0", Error: "owned failure"},
		{Module: "example.invalid/c", Version: "v1.0.0", Error: "owned failure"},
	}}
	if err := writeShardedReport(root, base); err != nil {
		t.Fatal(err)
	}
	discoveryRetrySetManifestCursor(t, root, &moduleVersion{Path: "example.invalid/b", Version: "v1.0.0"})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "owned persistent failure", http.StatusNotFound)
	}))
	defer server.Close()
	want := []moduleVersion{{Path: "example.invalid/c", Version: "v1.0.0"}, {Path: "example.invalid/a", Version: "v1.0.0"}}
	loads := 0
	cfg := config{limit: 2, workers: 1, maxZipSize: defaultMaxZipSize, proxyURL: server.URL,
		loadState: func(modules []moduleVersion) (scanBatchState, error) {
			loads++
			if !reflect.DeepEqual(modules, want) {
				t.Fatalf("loader received non-queue modules: %+v want %+v", modules, want)
			}
			return scanBatchState{}, nil
		}}
	report, err := retryFailuresStreaming(context.Background(), server.Client(), cfg, root)
	if err != nil || loads != 1 || report.UniqueModules != 2 || !reflect.DeepEqual(report.RetryAfter, &want[1]) ||
		len(report.IndexRanges) != 0 || report.IndexEntries != 0 || report.Since != "" || report.NextSince != "" || report.NextBefore != "" {
		t.Fatalf("retry input-boundary/range contract failed: %+v loads=%d error=%v", report, loads, err)
	}
	if len(report.Failures) != 2 || report.Failures[0].Module != want[1].Path || report.Failures[1].Module != want[0].Path {
		t.Fatalf("fixture did not independently reorder returned failures: %+v", report.Failures)
	}
	if err := writeShardedReportStreaming(root, report); err != nil {
		t.Fatal(err)
	}
	scan, err := scanShardedReport(root, nil)
	if err != nil || !reflect.DeepEqual(scan.metadata.RetryAfter, &want[1]) {
		t.Fatalf("input boundary not published: %+v %v", scan.metadata.RetryAfter, err)
	}
	stop := errors.New("owned batch-state error")
	cfg.loadState = func([]moduleVersion) (scanBatchState, error) { return scanBatchState{}, stop }
	if _, err := retryFailuresStreaming(context.Background(), server.Client(), cfg, root); !errors.Is(err, stop) {
		t.Fatalf("batch-state failure not retained: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(empty, discoveryReport{RetryAfter: &want[0]}); err != nil {
		t.Fatal(err)
	}
	cfg.loadState = func(modules []moduleVersion) (scanBatchState, error) {
		if len(modules) != 0 {
			t.Fatalf("empty retry ledger provided modules: %+v", modules)
		}
		return scanBatchState{}, nil
	}
	report, err = retryFailuresStreaming(context.Background(), server.Client(), cfg, empty)
	if err != nil || report.RetryAfter == nil || *report.RetryAfter != (moduleVersion{}) {
		t.Fatalf("empty retry did not request explicit clear: %+v %v", report, err)
	}
	if err := writeShardedReportStreaming(empty, report); err != nil {
		t.Fatal(err)
	}
	scan, err = scanShardedReport(empty, nil)
	if err != nil || scan.metadata.RetryAfter != nil {
		t.Fatalf("empty retry persisted a nonnil/empty marker: %+v %v", scan.metadata.RetryAfter, err)
	}
}

func discoveryRetryQueueUnderTest(root string, limit int) ([]moduleVersion, error) {
	return loadFailureRetryQueue(root, limit)
}

func TestDiscoveryRetryQueueBoundedDefaultMajorAndRotation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ledger")
	base := discoveryReport{Failures: []scanFailure{
		{Module: "example.invalid/a", Version: "v0.9.0", Error: "owned failure"},
		{Module: "example.invalid/a", Version: "v1.9.0", Error: "owned older failure"},
		{Module: "example.invalid/a", Version: "v1.10.0", Error: "owned latest line failure"},
		{Module: "example.invalid/a", Version: "@latest", Error: "owned resolution failure"},
		{Module: "example.invalid/b", Version: "v1.0.0", Error: "owned failure"},
	}}
	if err := writeShardedReport(root, base); err != nil {
		t.Fatal(err)
	}
	all := []moduleVersion{{Path: "example.invalid/a", Version: "v0.9.0"}, {Path: "example.invalid/a", Version: "v1.10.0"},
		{Path: "example.invalid/a", Version: "@latest"}, {Path: "example.invalid/b", Version: "v1.0.0"}}
	for _, test := range []struct {
		name   string
		cursor *moduleVersion
		want   []moduleVersion
	}{
		{name: "first", want: all[:2]},
		{name: "same-major old cursor", cursor: &moduleVersion{Path: "example.invalid/a", Version: "v1.9.0"}, want: all[1:3]},
		{name: "last wraps", cursor: &all[3], want: all[:2]},
		{name: "removed boundary", cursor: &moduleVersion{Path: "example.invalid/az", Version: "v1.0.0"}, want: []moduleVersion{all[3], all[0]}},
	} {
		t.Run(test.name, func(t *testing.T) {
			discoveryRetrySetManifestCursor(t, root, test.cursor)
			got, err := discoveryRetryQueueUnderTest(root, 2)
			if err != nil || !reflect.DeepEqual(got, test.want) || cap(got) > 2 {
				t.Fatalf("bounded major/rotation queue=%+v cap=%d want=%+v error=%v", got, cap(got), test.want, err)
			}
		})
	}
	if got, err := discoveryRetryQueueUnderTest(root, -1); err == nil || got != nil {
		t.Fatalf("negative retry budget accepted: %+v %v", got, err)
	}
	large := filepath.Join(t.TempDir(), "ledger")
	var failures []scanFailure
	for i := 0; i < defaultScanLimit+17; i++ {
		failures = append(failures, scanFailure{Module: fmt.Sprintf("example.invalid/%05d", i), Version: "v1.0.0", Error: "owned failure"})
	}
	if err := writeShardedReport(large, discoveryReport{Failures: failures}); err != nil {
		t.Fatal(err)
	}
	if got, err := discoveryRetryQueueUnderTest(large, 0); err != nil || len(got) != defaultScanLimit || cap(got) > defaultScanLimit {
		t.Fatalf("zero/default budget escaped bound: len=%d cap=%d error=%v", len(got), cap(got), err)
	}
}

func TestDiscoveryRetryQueueDrainsUnselectedTailAndCounts(t *testing.T) {
	for _, damage := range []string{"tail", "counts"} {
		t.Run(damage, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "ledger")
			if err := writeShardedReport(root, discoveryReport{Failures: []scanFailure{
				{Module: "example.invalid/a", Version: "v1.0.0", Error: "owned failure"},
				{Module: "example.invalid/b", Version: "v1.0.0", Error: "owned failure"},
			}}); err != nil {
				t.Fatal(err)
			}
			if damage == "tail" {
				if err := os.WriteFile(filepath.Join(root, "records", "ff.jsonl"), []byte("owned invalid unselected tail\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				discoveryRetryEditManifest(t, root, func(manifest map[string]any) { manifest["failure_records"] = float64(3) })
			}
			if got, err := discoveryRetryQueueUnderTest(root, 1); err == nil || got != nil {
				t.Fatalf("bounded queue exposed provisional records before full validation: %+v %v", got, err)
			}
		})
	}
}

func TestDiscoveryRetryQueueMatchesLegacyMajorSelectionWithBoundedBuffers(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ledger")
	var failures []scanFailure
	for _, path := range []string{"example.invalid/a", "example.invalid/b", "example.invalid/c"} {
		for _, version := range []string{"v0.1.0", "v0.9.0", "v1.9.0", "v1.10.0", "v2.0.0", "v10.0.0", "!old", "z-opaque", "@latest"} {
			failures = append(failures, scanFailure{Module: path, Version: version, Error: "owned failure"})
		}
	}
	base := discoveryReport{Failures: failures}
	if err := writeShardedReport(root, base); err != nil {
		t.Fatal(err)
	}
	all := modulesForFailureRetry(base)
	for _, cursor := range []*moduleVersion{nil, &all[3], &all[len(all)-1], {Path: "example.invalid/ba", Version: "v1.0.0"}} {
		discoveryRetrySetManifestCursor(t, root, cursor)
		for _, limit := range []int{1, 2, 5, len(all) + 1} {
			var want []moduleVersion
			for _, item := range all {
				if cursor == nil || compareRetryModules(item, *cursor) > 0 {
					want = append(want, item)
				}
			}
			if cursor != nil {
				for _, item := range all {
					if compareRetryModules(item, *cursor) <= 0 {
						want = append(want, item)
					}
				}
			}
			if len(want) > limit {
				want = want[:limit]
			}
			got, err := loadFailureRetryQueue(root, limit)
			if err != nil || !reflect.DeepEqual(got, want) || cap(got) > limit {
				t.Fatalf("cursor=%+v limit=%d queue=%+v cap=%d reference=%+v error=%v", cursor, limit, got, cap(got), want, err)
			}
		}
	}
	for _, limit := range []int{1, 2, 7} {
		var queue []moduleVersion
		for i := len(all) - 1; i >= 0; i-- {
			queue = retainRetryModule(queue, all[i], limit)
			if len(queue) > limit || cap(queue) > limit {
				t.Fatalf("candidate buffer exceeded budget: len=%d cap=%d limit=%d", len(queue), cap(queue), limit)
			}
		}
		if !reflect.DeepEqual(queue, all[:limit]) {
			t.Fatalf("physical reverse-order candidates differ: %+v", queue)
		}
	}
}

func TestDiscoveryRetryMetadataOptionalStrictAndMerge(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(root, discoveryReport{}); err != nil {
		t.Fatal(err)
	}
	cursor := moduleVersion{Path: "example.invalid/gone", Version: "@latest"}
	discoveryRetrySetManifestCursor(t, root, &cursor)
	scan, err := scanShardedReport(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := discoveryRetryJSONCursor(t, scan.metadata); !reflect.DeepEqual(got, &cursor) {
		t.Fatalf("streaming metadata discarded optional retry marker: %+v", got)
	}
	for _, invalid := range []moduleVersion{{Path: "only-path"}, {Version: "v1.0.0"}, {}} {
		discoveryRetrySetManifestCursor(t, root, &invalid)
		if _, err := scanShardedReport(root, nil); err == nil {
			t.Fatalf("persisted half/empty retry marker accepted: %+v", invalid)
		}
	}
	discoveryRetrySetManifestCursor(t, root, nil)
	if _, err := scanShardedReport(root, nil); err != nil {
		t.Fatal("old schema2 manifest without retry marker is not compatible", err)
	}
	base := discoveryRetryReportWithCursor(t, cursor)
	for _, test := range []struct {
		name   string
		update discoveryReport
		want   *moduleVersion
	}{
		{name: "preserve", want: &cursor},
		{name: "clear", update: discoveryRetryReportWithCursor(t, moduleVersion{})},
		{name: "replace", update: discoveryRetryReportWithCursor(t, moduleVersion{Path: "example.invalid/new", Version: "v1.10.0"}),
			want: &moduleVersion{Path: "example.invalid/new", Version: "v1.10.0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			merged, err := mergeDiscoveryReports(base, test.update)
			if err != nil || !reflect.DeepEqual(discoveryRetryJSONCursor(t, merged), test.want) {
				t.Fatalf("retry metadata merge lost preserve/clear/replace: %+v %v", merged, err)
			}
		})
	}
	for _, bad := range []moduleVersion{{Path: "only-path"}, {Version: "v1.0.0"}} {
		if _, err := mergeDiscoveryReports(base, discoveryRetryReportWithCursor(t, bad)); err == nil {
			t.Fatalf("merge accepted half retry marker %+v", bad)
		}
	}
}

func discoveryRetryEditManifest(t *testing.T, root string, edit func(map[string]any)) {
	t.Helper()
	file := filepath.Join(root, "manifest.json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	edit(manifest)
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func discoveryRetrySetManifestCursor(t *testing.T, root string, cursor *moduleVersion) {
	t.Helper()
	discoveryRetryEditManifest(t, root, func(manifest map[string]any) {
		if cursor == nil {
			delete(manifest, "retry_after")
		} else {
			manifest["retry_after"] = cursor
		}
	})
}

func discoveryRetryJSONCursor(t *testing.T, value any) *moduleVersion {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Cursor *moduleVersion `json:"retry_after"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result.Cursor
}

func discoveryRetryReportWithCursor(t *testing.T, cursor moduleVersion) discoveryReport {
	t.Helper()
	data, err := json.Marshal(map[string]any{"retry_after": cursor})
	if err != nil {
		t.Fatal(err)
	}
	var report discoveryReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report
}
