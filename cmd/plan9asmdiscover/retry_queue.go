package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

func retryFailuresStreaming(ctx context.Context, client *http.Client, cfg config, reportPath string) (discoveryReport, error) {
	modules, err := loadFailureRetryQueue(reportPath, cfg.limit)
	if err != nil {
		return discoveryReport{}, err
	}
	cfg, err = prepareScanBatch(ctx, cfg, modules)
	if err != nil {
		return discoveryReport{}, err
	}
	matched, failures, scanned, skipped := inspectModules(ctx, client, cfg.proxyURL, modules, cfg.seen, cfg.sourceSeen,
		cfg.workers, cfg.maxZipSize)
	// Input queue order includes wraparound. Result slices are sorted by their
	// own keys and must never determine the next fairness boundary.
	cursor := &moduleVersion{}
	if len(modules) > 0 {
		*cursor = modules[len(modules)-1]
	}
	return discoveryReport{
		SchemaVersion: discoverySchema, GeneratedAt: time.Now().UTC(),
		UniqueModules: len(modules), Skipped: skipped,
		Scanned: scanned, Matched: matched, Failures: failures, RetryAfter: cursor,
	}, nil
}

// A nil update preserves the previous marker. An explicitly empty update
// clears it; publishers must omit the cleared marker rather than persist {}.
func cloneRetryAfter(cursor *moduleVersion) *moduleVersion {
	if cursor == nil || cursor.Path == "" && cursor.Version == "" {
		return nil
	}
	copy := *cursor
	return &copy
}

func validateRetryAfter(cursor *moduleVersion, allowClear bool) error {
	if cursor == nil || allowClear && cursor.Path == "" && cursor.Version == "" {
		return nil
	}
	if cursor.Path == "" || cursor.Version == "" {
		return fmt.Errorf("invalid retry_after: module and version must both be nonempty")
	}
	return nil
}

func compareRetryModules(a, b moduleVersion) int {
	if compared := strings.Compare(a.Path, b.Path); compared != 0 {
		return compared
	}
	return compareModuleCandidates(a, b)
}

// retainRetryModule keeps the smallest limit keys, with capacity bounded too.
// Physical shard order is unrelated to the logical queue's module order.
func retainRetryModule(queue []moduleVersion, item moduleVersion, limit int) []moduleVersion {
	i := sort.Search(len(queue), func(i int) bool { return compareRetryModules(queue[i], item) >= 0 })
	if i < len(queue) && compareRetryModules(queue[i], item) == 0 || i == limit {
		return queue
	}
	if len(queue) < limit {
		if len(queue) == cap(queue) {
			capacity := 2 * cap(queue)
			if capacity < 1 {
				capacity = 1
			}
			if capacity > limit {
				capacity = limit
			}
			grown := make([]moduleVersion, len(queue), capacity)
			copy(grown, queue)
			queue = grown
		}
		queue = queue[:len(queue)+1]
	}
	copy(queue[i+1:], queue[i:len(queue)-1])
	queue[i] = item
	return queue
}

// loadFailureRetryQueue validates every physical record through EOF, counts
// and generation readback. It retains two limit-sized queue buffers and at
// most three current-module line candidates, never a full failure/module map.
func loadFailureRetryQueue(reportPath string, limit int) ([]moduleVersion, error) {
	if limit < 0 {
		return nil, fmt.Errorf("failure retry limit must be nonnegative")
	}
	if limit == 0 {
		limit = defaultScanLimit
	}
	// Read only the marker before starting the visitor. The authoritative scan
	// still validates the complete manifest and generation, and its marker
	// must match this provisional selection boundary before results escape.
	manifestPath := filepath.Join(reportPath, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read retry manifest %q: %w", manifestPath, err)
	}
	var manifest shardedManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode retry manifest %q: %w", manifestPath, err)
	}
	if err := validateRetryAfter(manifest.RetryAfter, false); err != nil {
		return nil, err
	}
	cursor := cloneRetryAfter(manifest.RetryAfter)
	var after, wrapped []moduleVersion
	accept := func(item moduleVersion) {
		if item.Path == "" {
			return
		}
		if cursor == nil || compareRetryModules(item, *cursor) > 0 {
			after = retainRetryModule(after, item, limit)
		} else {
			wrapped = retainRetryModule(wrapped, item, limit)
		}
	}
	var path, major string
	var valid, invalid, latest moduleVersion
	flush := func() {
		accept(valid)
		accept(invalid)
		accept(latest)
		valid, invalid, latest = moduleVersion{}, moduleVersion{}, moduleVersion{}
		major = ""
	}
	scan, err := scanShardedReport(reportPath, func(item shardedRecord) error {
		if item.Kind != "failure" {
			return nil
		}
		if path != item.Module {
			flush()
			path = item.Module
		}
		candidate := moduleVersion{Path: item.Module, Version: item.Version}
		switch {
		case item.Version == "@latest":
			latest = candidate
		case !semver.IsValid(item.Version):
			// Legacy failures may carry opaque versions. They share the old
			// empty-major checkpoint and can straddle @latest physically.
			invalid = candidate
		default:
			if nextMajor := semver.Major(item.Version); nextMajor != major {
				accept(valid)
				major = nextMajor
			}
			valid = candidate
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if (cursor == nil) != (scan.metadata.RetryAfter == nil) || cursor != nil && *cursor != *scan.metadata.RetryAfter {
		return nil, fmt.Errorf("retry manifest marker changed during queue selection")
	}
	flush()
	count := len(after) + len(wrapped)
	if count > limit {
		count = limit
	}
	queue := make([]moduleVersion, 0, count)
	queue = append(queue, after...)
	queue = append(queue, wrapped[:count-len(after)]...)
	return queue, nil
}
