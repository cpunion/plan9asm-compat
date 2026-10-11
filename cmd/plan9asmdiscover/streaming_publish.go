package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

// Publication retains the update batch and one complete old module. A module
// has one shard, so the reference merge can be applied to each module without
// building ledger-wide record slices or version maps.
func writeShardedReportStreaming(reportPath string, update discoveryReport) (returnErr error) {
	release, err := acquireLedgerLock(reportPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := release(); returnErr == nil && err != nil {
			returnErr = err
		}
	}()

	var previous *publicationBase
	if info, err := os.Stat(reportPath); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("write sharded report %q: path already exists and is not a directory", reportPath)
		}
		previous, err = openPublicationBase(reportPath)
		if err != nil {
			return fmt.Errorf("update sharded report %q: %w", reportPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("write sharded report %q: %w", reportPath, err)
	}
	var baseMetadata discoveryReport
	if previous != nil {
		baseMetadata = previous.metadata
	}
	metadata, err := mergeDiscoveryReports(baseMetadata, publicationMetadata(update))
	if err != nil {
		return fmt.Errorf("merge publication metadata: %w", err)
	}
	updates := publicationUpdateModules(update)
	var ordered [256][]string
	for module := range updates {
		bucket := sha256.Sum256([]byte(module))
		ordered[bucket[0]] = append(ordered[bucket[0]], module)
	}
	for bucket := range ordered {
		sort.Strings(ordered[bucket])
	}

	temporary, err := os.MkdirTemp(filepath.Dir(reportPath), ".plan9asmdiscover-streaming-*")
	if err != nil {
		return fmt.Errorf("create publication staging directory: %w", err)
	}
	defer os.RemoveAll(temporary)
	if err := os.Mkdir(filepath.Join(temporary, "records"), 0o755); err != nil {
		return fmt.Errorf("create publication records directory: %w", err)
	}
	publisher := publicationShardWriter{root: temporary, summary: summarizeLedger(metadata)}
	defer publisher.closeOnError()
	bucket, nextUpdate := -1, 0
	var visited [256]bool
	var oldModule string
	var oldRecords discoveryReport
	emit := func(old, change discoveryReport) error {
		merged, err := mergeDiscoveryReports(old, change)
		if err != nil {
			return fmt.Errorf("merge complete module: %w", err)
		}
		return publisher.emitModule(merged)
	}
	flushModule := func() error {
		if oldModule == "" {
			return nil
		}
		for nextUpdate < len(ordered[bucket]) && ordered[bucket][nextUpdate] < oldModule {
			if err := emit(discoveryReport{}, updates[ordered[bucket][nextUpdate]]); err != nil {
				return err
			}
			nextUpdate++
		}
		var change discoveryReport
		if nextUpdate < len(ordered[bucket]) && ordered[bucket][nextUpdate] == oldModule {
			change = updates[oldModule]
			nextUpdate++
		}
		if err := emit(oldRecords, change); err != nil {
			return err
		}
		oldModule, oldRecords = "", discoveryReport{}
		return nil
	}
	finishBucket := func() error {
		for nextUpdate < len(ordered[bucket]) {
			if err := emit(discoveryReport{}, updates[ordered[bucket][nextUpdate]]); err != nil {
				return err
			}
			nextUpdate++
		}
		return publisher.finishShard()
	}
	if previous != nil {
		_, err := scanShardedReport(reportPath, func(record shardedRecord) error {
			shard := sha256.Sum256([]byte(record.Module))
			if int(shard[0]) != bucket {
				if err := flushModule(); err != nil {
					return err
				}
				if bucket >= 0 {
					if err := finishBucket(); err != nil {
						return err
					}
					visited[bucket] = true
				}
				bucket, nextUpdate = int(shard[0]), 0
				if visited[bucket] {
					return fmt.Errorf("publication revisited logical shard %02x", bucket)
				}
			} else if record.Module != oldModule {
				if err := flushModule(); err != nil {
					return err
				}
			}
			oldModule = record.Module
			return appendPublicationRecord(&oldRecords, record)
		})
		if err != nil {
			return fmt.Errorf("validate previous publication input: %w", err)
		}
	}
	if err := flushModule(); err != nil {
		return err
	}
	if bucket >= 0 {
		if err := finishBucket(); err != nil {
			return err
		}
		visited[bucket] = true
	}
	// File creation order need not be numeric: unique uppercase shard names
	// sort differently, but records within each logical bucket remain ordered.
	for i := range ordered {
		if visited[i] {
			continue
		}
		bucket, nextUpdate = i, 0
		if err := finishBucket(); err != nil {
			return err
		}
	}
	metadata.UniqueModules = publisher.summary.UniqueModules
	if err := writePublicationManifest(temporary, metadata, publisher.summary); err != nil {
		return err
	}
	actual, err := readShardedSummary(temporary)
	if err != nil {
		return fmt.Errorf("validate staged publication: %w", err)
	}
	if !reflect.DeepEqual(actual, publisher.summary) {
		return fmt.Errorf("staged publication summary differs: got %+v, want %+v", actual, publisher.summary)
	}
	if previous != nil {
		if err := previous.verify(reportPath); err != nil {
			return err
		}
	}
	return replacePublicationDirectory(temporary, reportPath, previous != nil, os.Rename)
}

// Capture only bounded generation metadata before the old-record walk. The
// complete scanner validates every record; this snapshot also binds that walk
// to the metadata used for cursor/range merging, even across a replacement.
type publicationBase struct {
	metadata   discoveryReport
	manifest   []byte
	root       os.FileInfo
	records    os.FileInfo
	shards     []string
	identities []os.FileInfo
}

func openPublicationBase(root string) (*publicationBase, error) {
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var manifest shardedManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	base := &publicationBase{
		manifest: data,
		metadata: discoveryReport{
			SchemaVersion: manifest.SchemaVersion, GeneratedAt: manifest.GeneratedAt,
			Since: manifest.Since, NextSince: manifest.NextSince,
			ScanDirection: manifest.ScanDirection, NextBefore: manifest.NextBefore,
			IndexRanges: manifest.IndexRanges, IndexEntries: manifest.IndexEntries,
			UniqueModules: manifest.UniqueModules, Skipped: manifest.Skipped,
			RetryAfter: cloneRetryAfter(manifest.RetryAfter),
		},
	}
	base.root, err = os.Stat(root)
	if err != nil {
		return nil, err
	}
	recordsDir := filepath.Join(root, "records")
	base.records, err = os.Stat(recordsDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		name := filepath.Join(recordsDir, entry.Name())
		info, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		base.shards = append(base.shards, name)
		base.identities = append(base.identities, info)
	}
	return base, nil
}

func (b *publicationBase) verify(root string) error {
	return verifyShardedScanGeneration(root, b.manifest, b.root, b.records, b.shards, b.identities)
}

func publicationMetadata(report discoveryReport) discoveryReport {
	report.Scanned, report.Matched, report.Failures = nil, nil, nil
	return report
}

func publicationUpdateModules(report discoveryReport) map[string]discoveryReport {
	modules := make(map[string]discoveryReport)
	for _, record := range publicationRecords(report) {
		group := modules[record.Module]
		// These records are created from the typed batch, never arbitrary input.
		_ = appendPublicationRecord(&group, record)
		modules[record.Module] = group
	}
	return modules
}

func appendPublicationRecord(report *discoveryReport, record shardedRecord) error {
	switch record.Kind {
	case "scanned":
		report.Scanned = append(report.Scanned, moduleVersion{Path: record.Module, Version: record.Version})
	case "matched":
		report.Matched = append(report.Matched, candidate{
			Module: record.Module, Version: record.Version,
			Architectures: record.Architectures, AsmFiles: record.AsmFiles,
		})
	case "failure":
		report.Failures = append(report.Failures, scanFailure{Module: record.Module, Version: record.Version, Error: record.Error})
	default:
		return fmt.Errorf("unknown publication record kind %q", record.Kind)
	}
	return nil
}

func publicationRecords(report discoveryReport) []shardedRecord {
	records := make([]shardedRecord, 0, len(report.Scanned)+len(report.Matched)+len(report.Failures))
	for _, item := range report.Scanned {
		records = append(records, shardedRecord{Kind: "scanned", Module: item.Path, Version: item.Version})
	}
	for _, item := range report.Matched {
		records = append(records, shardedRecord{
			Kind: "matched", Module: item.Module, Version: item.Version,
			Architectures: item.Architectures, AsmFiles: item.AsmFiles,
		})
	}
	for _, item := range report.Failures {
		records = append(records, shardedRecord{Kind: "failure", Module: item.Module, Version: item.Version, Error: item.Error})
	}
	// Duplicate batch failure payloads deliberately retain last-input-wins.
	sort.SliceStable(records, func(i, j int) bool { return compareShardedRecords(records[i], records[j]) < 0 })
	return records
}

type publicationShardWriter struct {
	root    string
	name    string
	file    *os.File
	encoder *json.Encoder
	summary ledgerSummary
}

func (p *publicationShardWriter) emitModule(report discoveryReport) error {
	counts := summarizeLedger(report)
	p.summary.UniqueModules += counts.UniqueModules
	p.summary.ScannedRecords += counts.ScannedRecords
	p.summary.MatchedRecords += counts.MatchedRecords
	p.summary.FailureRecords += counts.FailureRecords
	p.summary.AssemblyFiles += counts.AssemblyFiles
	for _, record := range publicationRecords(report) {
		bucket := sha256.Sum256([]byte(record.Module))
		name := fmt.Sprintf("%02x.jsonl", bucket[0])
		if p.file == nil {
			file, err := os.OpenFile(filepath.Join(p.root, "records", name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
			if err != nil {
				return fmt.Errorf("create publication shard: %w", err)
			}
			p.name, p.file, p.encoder = name, file, json.NewEncoder(file)
		}
		if p.name != name {
			return fmt.Errorf("publication crossed an ordered shard boundary")
		}
		if err := p.encoder.Encode(record); err != nil {
			return fmt.Errorf("encode publication record: %w", err)
		}
	}
	return nil
}

func (p *publicationShardWriter) finishShard() error {
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file, p.encoder = nil, nil
	if err != nil {
		return fmt.Errorf("close publication shard: %w", err)
	}
	return nil
}

func (p *publicationShardWriter) closeOnError() {
	if p.file != nil {
		_ = p.file.Close()
	}
}

func writePublicationManifest(root string, metadata discoveryReport, summary ledgerSummary) error {
	manifest := shardedManifest{
		SchemaVersion: metadata.SchemaVersion, Format: shardedFormat,
		GeneratedAt: metadata.GeneratedAt, Since: metadata.Since, NextSince: metadata.NextSince,
		ScanDirection: metadata.ScanDirection, NextBefore: metadata.NextBefore,
		IndexRanges: metadata.IndexRanges, IndexEntries: metadata.IndexEntries,
		UniqueModules: summary.UniqueModules, Skipped: metadata.Skipped,
		Scanned: summary.ScannedRecords, Matched: summary.MatchedRecords, Failures: summary.FailureRecords,
		ShardKey:   "sha256(module)[0]",
		RetryAfter: cloneRetryAfter(metadata.RetryAfter),
	}
	file, err := os.OpenFile(filepath.Join(root, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(manifest)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}

func replacePublicationDirectory(staging, destination string, exists bool, rename func(string, string) error) error {
	if !exists {
		return rename(staging, destination)
	}
	backup := staging + "-previous"
	if err := rename(destination, backup); err != nil {
		return fmt.Errorf("preserve previous ledger: %w", err)
	}
	if err := rename(staging, destination); err != nil {
		if restoreErr := rename(backup, destination); restoreErr != nil {
			return fmt.Errorf("publish ledger: %v (restore previous ledger: %v)", err, restoreErr)
		}
		return fmt.Errorf("publish ledger: %w", err)
	}
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("remove previous ledger after publication: %w", err)
	}
	return nil
}
