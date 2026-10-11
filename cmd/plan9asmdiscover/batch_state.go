package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type scanBatchState struct {
	seen        map[string]seenResult
	sourceSeen  map[string]seenResult
	checkpoints map[string]moduleCheckpoint
}

// Only exact active paths and their GitHub owner/repository case aliases are
// retained. Version lines and case-sensitive submodule suffixes stay distinct.
// Filtering never bypasses complete shard/range/generation validation.
func loadBatchState(paths []string, modules []moduleVersion) (scanBatchState, error) {
	interest := make(map[string]bool, len(modules))
	aliases := make(map[string]bool, len(modules))
	for _, item := range modules {
		interest[item.Path] = true
		if alias := sourcePathAlias(item.Path); alias != "" {
			aliases[alias] = true
		}
	}
	wanted := func(modulePath string) bool {
		return interest[modulePath] || aliases[sourcePathAlias(modulePath)]
	}
	state := scanBatchState{
		seen: make(map[string]seenResult), sourceSeen: make(map[string]seenResult),
		checkpoints: make(map[string]moduleCheckpoint),
	}
	visited := make(map[string]bool, len(paths))
	for _, reportPath := range paths {
		absolute, err := filepath.Abs(reportPath)
		if err != nil {
			return scanBatchState{}, err
		}
		if visited[absolute] {
			continue
		}
		visited[absolute] = true
		report, err := readBatchSource(reportPath, wanted)
		if err != nil {
			return scanBatchState{}, err
		}
		for _, item := range report.Scanned {
			rememberSeenResult(state.seen, scanKey(item), seenResult{})
			rememberSeenResult(state.sourceSeen, sourceScanKey(item), seenResult{})
		}
		for _, item := range report.Matched {
			version := moduleVersion{Path: item.Module, Version: item.Version}
			result := seenResult{Match: item}
			rememberSeenResult(state.seen, scanKey(version), result)
			rememberSeenResult(state.sourceSeen, sourceScanKey(version), result)
		}
		for _, checkpoint := range moduleCheckpoints(report) {
			chooseModuleCheckpoint(state.checkpoints, checkpoint.Path, checkpoint.Version)
		}
	}
	return state, nil
}

func prepareScanBatch(ctx context.Context, cfg config, modules []moduleVersion) (config, error) {
	if err := ctx.Err(); err != nil {
		return config{}, err
	}
	if cfg.loadState == nil {
		return cfg, nil
	}
	state, err := cfg.loadState(append([]moduleVersion(nil), modules...))
	if err != nil {
		return config{}, err
	}
	if err := ctx.Err(); err != nil {
		return config{}, err
	}
	cfg.seen, cfg.sourceSeen, cfg.checkpoints = state.seen, state.sourceSeen, state.checkpoints
	return cfg, nil
}

func sourcePathAlias(modulePath string) string {
	parts := strings.Split(modulePath, "/")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "github.com") {
		return ""
	}
	canonical := "github.com/" + strings.ToLower(parts[1]) + "/" + strings.ToLower(parts[2])
	if len(parts) > 3 {
		canonical += "/" + strings.Join(parts[3:], "/")
	}
	return canonical
}

func readBatchSource(reportPath string, wanted func(string) bool) (discoveryReport, error) {
	info, err := os.Stat(reportPath)
	if err != nil {
		return discoveryReport{}, fmt.Errorf("read batch source %q: %w", reportPath, err)
	}
	if !info.IsDir() {
		// Explicit legacy JSON/gzip is a compatibility import, not the normal
		// resident scanner database. Decode one source, filter, then release it.
		report, err := readSeenReport(reportPath)
		if err != nil {
			return discoveryReport{}, err
		}
		selected := report
		selected.Scanned, selected.Matched, selected.Failures = nil, nil, nil
		for _, item := range report.Scanned {
			if item.Path == "" || item.Version == "" {
				return discoveryReport{}, fmt.Errorf("seen report %q contains an incomplete scanned version", reportPath)
			}
			if wanted(item.Path) {
				selected.Scanned = append(selected.Scanned, item)
			}
		}
		for _, item := range report.Matched {
			if item.Module != "" && item.Version != "" && wanted(item.Module) {
				selected.Matched = append(selected.Matched, item)
			}
		}
		for _, item := range report.Failures {
			if item.Module != "" && item.Version != "" && wanted(item.Module) {
				selected.Failures = append(selected.Failures, item)
			}
		}
		return selected, nil
	}
	if _, err := os.Stat(filepath.Join(reportPath, "manifest.json")); err == nil {
		return readBatchShardedReport(reportPath, wanted)
	} else if !errors.Is(err, os.ErrNotExist) {
		return discoveryReport{}, fmt.Errorf("read sharded report %q: %w", reportPath, err)
	}

	// Legacy per-run collections keep their original WalkDir no-follow policy.
	// Consume each discovered source immediately, retaining only selected
	// records and combined range metadata, never a manifest or full-record list.
	var combined discoveryReport
	found := false
	err = filepath.WalkDir(reportPath, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != "manifest.json" {
			return nil
		}
		found = true
		report, err := readBatchShardedReport(filepath.Dir(name), wanted)
		if err != nil {
			return err
		}
		combined, err = mergeDiscoveryReports(combined, report)
		return err
	})
	if err != nil {
		return discoveryReport{}, fmt.Errorf("read sharded reports %q: %w", reportPath, err)
	}
	if !found {
		return discoveryReport{}, fmt.Errorf("read sharded reports %q: no manifest.json found", reportPath)
	}
	return combined, nil
}

func readBatchShardedReport(reportPath string, wanted func(string) bool) (discoveryReport, error) {
	var selected discoveryReport
	scan, err := scanShardedReport(reportPath, func(item shardedRecord) error {
		if !wanted(item.Module) {
			return nil
		}
		switch item.Kind {
		case "scanned":
			selected.Scanned = append(selected.Scanned, moduleVersion{Path: item.Module, Version: item.Version})
		case "matched":
			selected.Matched = append(selected.Matched, candidate{
				Module: item.Module, Version: item.Version, Architectures: item.Architectures, AsmFiles: item.AsmFiles,
			})
		case "failure":
			selected.Failures = append(selected.Failures, scanFailure{Module: item.Module, Version: item.Version, Error: item.Error})
		}
		return nil
	})
	if err != nil {
		return discoveryReport{}, err
	}
	report := scan.metadata
	report.Scanned, report.Matched, report.Failures = selected.Scanned, selected.Matched, selected.Failures
	sortDiscoveryReport(&report)
	return report, nil
}
