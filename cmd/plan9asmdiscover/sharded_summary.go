package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

type shardedScan struct {
	metadata discoveryReport
	summary  ledgerSummary
}

// readShardedSummary validates the complete input, not only the counts it
// displays. It retains manifest/range metadata, shard identities and at most
// the current/previous record, never a ledger-sized record slice or map.
func readShardedSummary(reportPath string) (ledgerSummary, error) {
	scan, err := scanShardedReport(reportPath, nil)
	if err != nil {
		return ledgerSummary{}, err
	}
	return scan.summary, nil
}

// A visitor is called only after the record's complete local validation. Its
// observations are provisional until this function succeeds: count and final
// generation checks still follow. The full import reader explicitly collects
// records through this same scanner; status and publication readback do not.
func scanShardedReport(reportPath string, visit func(shardedRecord) error) (shardedScan, error) {
	manifestPath := filepath.Join(reportPath, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return shardedScan{}, fmt.Errorf("read sharded report manifest %q: %w", manifestPath, err)
	}
	var manifest shardedManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return shardedScan{}, fmt.Errorf("decode sharded report manifest %q: %w", manifestPath, err)
	}
	if manifest.Format != shardedFormat {
		return shardedScan{}, fmt.Errorf("decode sharded report manifest %q: unsupported format %q", manifestPath, manifest.Format)
	}
	if manifest.SchemaVersion != discoverySchema {
		return shardedScan{}, fmt.Errorf("decode sharded report manifest %q: unsupported schema %d", manifestPath, manifest.SchemaVersion)
	}
	if manifest.ShardKey != "sha256(module)[0]" {
		return shardedScan{}, fmt.Errorf("decode sharded report manifest %q: unsupported shard key %q", manifestPath, manifest.ShardKey)
	}
	if err := validateRetryAfter(manifest.RetryAfter, false); err != nil {
		return shardedScan{}, fmt.Errorf("decode sharded report manifest %q: %w", manifestPath, err)
	}
	report := discoveryReport{
		SchemaVersion: manifest.SchemaVersion, GeneratedAt: manifest.GeneratedAt,
		Since: manifest.Since, NextSince: manifest.NextSince,
		ScanDirection: manifest.ScanDirection, NextBefore: manifest.NextBefore,
		IndexRanges: manifest.IndexRanges, IndexEntries: manifest.IndexEntries,
		UniqueModules: manifest.UniqueModules, Skipped: manifest.Skipped,
		RetryAfter: cloneRetryAfter(manifest.RetryAfter),
	}
	if len(report.IndexRanges) > 0 {
		report, err = upgradeDiscoveryReport(report)
		if err != nil {
			return shardedScan{}, fmt.Errorf("decode sharded report manifest %q: %w", manifestPath, err)
		}
		entries := 0
		for _, item := range report.IndexRanges {
			entries += item.IndexEntries
		}
		if entries != manifest.IndexEntries {
			return shardedScan{}, fmt.Errorf("decode sharded report manifest %q: index range count is %d, want index_entries %d", manifestPath, entries, manifest.IndexEntries)
		}
	}
	rootInfo, err := os.Stat(reportPath)
	if err != nil {
		return shardedScan{}, fmt.Errorf("stat sharded report %q: %w", reportPath, err)
	}
	recordsDir := filepath.Join(reportPath, "records")
	recordsInfo, err := os.Stat(recordsDir)
	if err != nil {
		return shardedScan{}, fmt.Errorf("stat sharded report records %q: %w", recordsDir, err)
	}
	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		return shardedScan{}, fmt.Errorf("list sharded report records %q: %w", reportPath, err)
	}
	shards, err := recordShardPaths(reportPath, entries)
	if err != nil {
		return shardedScan{}, err
	}
	summary := summarizeLedger(report)
	identities := make([]os.FileInfo, 0, len(shards))
	for _, shard := range shards {
		identity, err := scanRecordShard(shard, &summary, visit)
		if err != nil {
			return shardedScan{}, err
		}
		identities = append(identities, identity)
	}
	if summary.ScannedRecords != manifest.Scanned || summary.MatchedRecords != manifest.Matched || summary.FailureRecords != manifest.Failures {
		return shardedScan{}, fmt.Errorf(
			"read sharded report %q: record counts are scanned=%d/%d matched=%d/%d failures=%d/%d",
			reportPath, summary.ScannedRecords, manifest.Scanned, summary.MatchedRecords, manifest.Matched, summary.FailureRecords, manifest.Failures,
		)
	}
	if err := verifyShardedScanGeneration(reportPath, data, rootInfo, recordsInfo, shards, identities); err != nil {
		return shardedScan{}, err
	}
	return shardedScan{metadata: report, summary: summary}, nil
}

// Keep namespace validation independent of the host filesystem's case policy.
func recordShardPaths(reportPath string, entries []os.DirEntry) ([]string, error) {
	shards := make([]string, 0, len(entries))
	var seen [256]bool
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) != len("00.jsonl") || !strings.HasSuffix(name, ".jsonl") {
			return nil, fmt.Errorf("list sharded report records %q: unexpected entry %q", reportPath, name)
		}
		bucket, err := strconv.ParseUint(name[:2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("list sharded report records %q: invalid shard name %q", reportPath, name)
		}
		if seen[bucket] {
			return nil, fmt.Errorf("list sharded report records %q: duplicate logical record shard %q", reportPath, name)
		}
		seen[bucket] = true
		shards = append(shards, filepath.Join(reportPath, "records", name))
	}
	sort.Strings(shards)
	return shards, nil
}

func scanRecordShard(shard string, summary *ledgerSummary, visit func(shardedRecord) error) (os.FileInfo, error) {
	shardNumber, _ := strconv.ParseUint(filepath.Base(shard)[:2], 16, 8)
	file, err := os.Open(shard)
	if err != nil {
		return nil, fmt.Errorf("read record shard %q: %w", shard, err)
	}
	defer file.Close()
	identity, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat record shard %q: %w", shard, err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	line := 0
	var previous shardedRecord
	for scanner.Scan() {
		line++
		item, err := decodeRecordShardLine(shard, byte(shardNumber), line, previous, scanner.Bytes(), summary)
		if err != nil {
			return nil, err
		}
		previous = item
		if visit != nil {
			if err := visit(item); err != nil {
				return nil, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read record shard %q: %w", shard, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close record shard %q: %w", shard, err)
	}
	return identity, nil
}

// Full scans and transfer cursors share the exact line grammar. Cursor counts
// are provisional; only the complete initial/final scans authorize publication.
func decodeRecordShardLine(shard string, bucket byte, line int, previous shardedRecord, data []byte, summary *ledgerSummary) (shardedRecord, error) {
	var item shardedRecord
	if err := json.Unmarshal(data, &item); err != nil {
		return shardedRecord{}, fmt.Errorf("decode record shard %s:%d: %w", shard, line, err)
	}
	if item.Module == "" || item.Version == "" {
		return shardedRecord{}, fmt.Errorf("decode record shard %s:%d: incomplete module version", shard, line)
	}
	hash := sha256.Sum256([]byte(item.Module))
	if hash[0] != bucket {
		return shardedRecord{}, fmt.Errorf("decode record shard %s:%d: module %q belongs in %02x.jsonl", shard, line, item.Module, hash[0])
	}
	if line > 1 && compareShardedRecords(previous, item) >= 0 {
		return shardedRecord{}, fmt.Errorf("decode record shard %s:%d: records are duplicated or not in module/semver/kind order", shard, line)
	}
	switch item.Kind {
	case "scanned", "matched":
		if !semver.IsValid(item.Version) {
			return shardedRecord{}, fmt.Errorf("decode record shard %s:%d: invalid %s module version %q", shard, line, item.Kind, item.Version)
		}
		if item.Kind == "scanned" {
			summary.ScannedRecords++
		} else {
			summary.MatchedRecords++
			summary.AssemblyFiles += len(item.AsmFiles)
		}
	case "failure":
		summary.FailureRecords++
	default:
		return shardedRecord{}, fmt.Errorf("decode record shard %s:%d: unknown record kind %q", shard, line, item.Kind)
	}
	return item, nil
}

// Publication replaces the ledger directory. Do not return a summary assembled
// across two generations, even if their counts happen to agree. The bounded
// shard metadata additionally catches ordinary in-place edits/additions.
func verifyShardedScanGeneration(reportPath string, manifest []byte, root, records os.FileInfo, shards []string, identities []os.FileInfo) error {
	changed := func(name string) error {
		return fmt.Errorf("read sharded report %q: input changed during validation: %s", reportPath, name)
	}
	for _, directory := range []struct {
		name string
		info os.FileInfo
	}{{reportPath, root}, {filepath.Join(reportPath, "records"), records}} {
		current, err := os.Stat(directory.name)
		if err != nil {
			return fmt.Errorf("verify sharded report generation %q: %w", directory.name, err)
		}
		if !os.SameFile(directory.info, current) {
			return changed(directory.name)
		}
	}
	manifestPath := filepath.Join(reportPath, "manifest.json")
	current, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("verify sharded report manifest %q: %w", manifestPath, err)
	}
	if !bytes.Equal(manifest, current) {
		return changed(manifestPath)
	}
	entries, err := os.ReadDir(filepath.Join(reportPath, "records"))
	if err != nil {
		return fmt.Errorf("verify sharded report shards %q: %w", reportPath, err)
	}
	if len(entries) != len(shards) {
		return changed("record shard inventory")
	}
	for i, entry := range entries {
		if filepath.Join(reportPath, "records", entry.Name()) != shards[i] {
			return changed("record shard inventory")
		}
		info, err := os.Stat(shards[i])
		if err != nil {
			return fmt.Errorf("verify record shard %q: %w", shards[i], err)
		}
		previous := identities[i]
		if !os.SameFile(previous, info) || previous.Size() != info.Size() || previous.Mode() != info.Mode() || !previous.ModTime().Equal(info.ModTime()) {
			return changed(shards[i])
		}
	}
	return nil
}
