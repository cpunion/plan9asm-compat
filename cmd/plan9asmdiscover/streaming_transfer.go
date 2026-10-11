package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// mergeLedgerStreaming accepts one sharded ledger or a former per-run
// collection. Every input is validated completely; only metadata and current
// module groups are retained. Metadata is merged once per input, not per module.
func mergeLedgerStreaming(destination, source string) (returnErr error) {
	source, destination, err := streamingTransferPaths(source, destination)
	if err != nil {
		return err
	}
	sources, err := captureTransferSources(source)
	if err != nil {
		return err
	}
	locks := append([]string{source, destination}, sources.roots...)
	sort.Strings(locks)
	for i, name := range locks {
		if i > 0 && name == locks[i-1] {
			continue
		}
		release, err := acquireLedgerLock(name)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, release()) }()
	}
	if err := sources.verify(); err != nil {
		return err
	}
	inputs := make([]*publicationBase, 0, len(sources.roots))
	var sourceMetadata discoveryReport
	for _, root := range sources.roots {
		input, err := openTransferInput(root)
		if err != nil {
			return err
		}
		inputs = append(inputs, input)
		sourceMetadata, err = mergeDiscoveryReports(sourceMetadata, input.metadata)
		if err != nil {
			return fmt.Errorf("merge collection metadata: %w", err)
		}
	}
	var previous *publicationBase
	var oldMetadata discoveryReport
	if info, err := os.Stat(destination); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("streaming transfer destination is not a directory")
		}
		previous, err = openTransferInput(destination)
		if err != nil {
			return err
		}
		oldMetadata = previous.metadata
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	metadata, err := mergeDiscoveryReports(oldMetadata, sourceMetadata)
	if err != nil {
		return fmt.Errorf("merge transfer metadata: %w", err)
	}
	oldShards := transferShardBuckets(previous)
	newShards := make([][256]string, len(inputs))
	for i, input := range inputs {
		newShards[i] = transferShardBuckets(input)
	}
	temporary, err := os.MkdirTemp(filepath.Dir(destination), ".plan9asmdiscover-transfer-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(temporary); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("clean transfer staging: %w", err))
		}
	}()
	if err := os.Mkdir(filepath.Join(temporary, "records"), 0o755); err != nil {
		return err
	}
	publisher := publicationShardWriter{root: temporary, summary: summarizeLedger(metadata)}
	defer publisher.closeOnError()
	for bucket := 0; bucket < 256; bucket++ {
		paths := make([]string, len(inputs))
		for i := range inputs {
			paths[i] = newShards[i][bucket]
		}
		if err := transferCollectionBucket(&publisher, oldShards[bucket], paths); err != nil {
			return err
		}
	}
	metadata.UniqueModules = publisher.summary.UniqueModules
	if err := writePublicationManifest(temporary, metadata, publisher.summary); err != nil {
		return err
	}
	actual, err := readShardedSummary(temporary)
	if err != nil {
		return fmt.Errorf("validate transfer staging: %w", err)
	}
	if !reflect.DeepEqual(actual, publisher.summary) {
		return fmt.Errorf("transfer staging summary differs from emitted module counts")
	}
	// Extra complete reads are linear, not per-module rescans. They preserve
	// all EOF/count/range checks and bind final bytes to the initial snapshots.
	if err := verifyTransferGeneration(sources, inputs, destination, previous); err != nil {
		return err
	}
	return replacePublicationDirectory(temporary, destination, previous != nil, os.Rename)
}

func verifyTransferGeneration(sources *transferSources, inputs []*publicationBase, destination string, previous *publicationBase) error {
	for i, root := range sources.roots {
		if _, err := scanShardedReport(root, nil); err != nil {
			return err
		}
		if err := inputs[i].verify(root); err != nil {
			return err
		}
	}
	if previous != nil {
		if _, err := scanShardedReport(destination, nil); err != nil {
			return err
		}
		if err := previous.verify(destination); err != nil {
			return err
		}
	}
	return sources.verify()
}

func openTransferInput(root string) (*publicationBase, error) {
	base, err := openPublicationBase(root)
	if err != nil {
		return nil, err
	}
	scan, err := scanShardedReport(root, nil)
	if err != nil {
		return nil, err
	}
	if err := base.verify(root); err != nil {
		return nil, err
	}
	base.metadata = scan.metadata
	return base, nil
}

func transferShardBuckets(base *publicationBase) [256]string {
	var buckets [256]string
	if base != nil {
		// The shared initial scanner already rejects duplicate logical buckets.
		for _, name := range base.shards {
			bucket, _ := strconv.ParseUint(filepath.Base(name)[:2], 16, 8)
			buckets[bucket] = name
		}
	}
	return buckets
}

func transferRecordBucket(publisher *publicationShardWriter, oldPath, newPath string) error {
	oldStream, newStream := newTransferModuleIterator(oldPath), newTransferModuleIterator(newPath)
	return transferModuleStreams(publisher, oldStream, newStream)
}

func transferModuleStreams(publisher *publicationShardWriter, oldStream, newStream *transferModuleIterator) error {
	defer oldStream.close()
	defer newStream.close()
	old, hasOld, err := oldStream.next()
	if err != nil {
		return err
	}
	change, hasChange, err := newStream.next()
	if err != nil {
		return err
	}
	for hasOld || hasChange {
		useOld, useChange := hasOld, hasChange
		if hasOld && hasChange {
			order := strings.Compare(old.module, change.module)
			useOld, useChange = order <= 0, order >= 0
		}
		var base, update discoveryReport
		if useOld {
			base = old.report
		}
		if useChange {
			update = change.report
		}
		merged, err := mergeDiscoveryReports(base, update)
		if err != nil {
			return fmt.Errorf("merge transfer module: %w", err)
		}
		if err := publisher.emitModule(merged); err != nil {
			return err
		}
		if useOld {
			old, hasOld, err = oldStream.next()
			if err != nil {
				return err
			}
		}
		if useChange {
			change, hasChange, err = newStream.next()
			if err != nil {
				return err
			}
		}
	}
	return publisher.finishShard()
}

type transferModuleGroup struct {
	module string
	report discoveryReport
}

type transferModuleIterator struct {
	groups chan transferModuleGroup
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

// Unbuffered handoff bounds retained payload by complete current modules. Every
// early receiver/decoder error cancels and joins both producers before return.
func newTransferModuleIterator(shard string) *transferModuleIterator {
	ctx, cancel := context.WithCancel(context.Background())
	iterator := &transferModuleIterator{
		groups: make(chan transferModuleGroup), done: make(chan struct{}), cancel: cancel,
	}
	go func() {
		defer close(iterator.done)
		defer close(iterator.groups)
		if shard == "" {
			return
		}
		var group transferModuleGroup
		flush := func() error {
			if group.module == "" {
				return nil
			}
			select {
			case iterator.groups <- group:
				group = transferModuleGroup{}
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		_, iterator.err = scanRecordShard(shard, &ledgerSummary{}, func(record shardedRecord) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if group.module != record.Module {
				if err := flush(); err != nil {
					return err
				}
				group.module = record.Module
			}
			return appendPublicationRecord(&group.report, record)
		})
		if iterator.err == nil {
			iterator.err = flush()
		}
	}()
	return iterator
}

func (i *transferModuleIterator) next() (transferModuleGroup, bool, error) {
	group, ok := <-i.groups
	if !ok {
		<-i.done
		return transferModuleGroup{}, false, i.err
	}
	return group, true, nil
}

func (i *transferModuleIterator) close() {
	i.cancel()
	<-i.done
}

func streamingTransferPaths(source, destination string) (string, string, error) {
	source, err := filepath.Abs(source)
	if err != nil {
		return "", "", err
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return "", "", err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return "", "", err
	}
	// Resolve the longest existing parent, including existing case/symlink aliases.
	for probe := destination; ; probe = filepath.Dir(probe) {
		if _, err := os.Lstat(probe); err == nil {
			resolved, err := filepath.EvalSymlinks(probe)
			if err != nil {
				return "", "", err
			}
			remainder, err := filepath.Rel(probe, destination)
			if err != nil {
				return "", "", err
			}
			destination = filepath.Join(resolved, remainder)
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", "", err
		}
	}
	for _, pair := range [][2]string{{source, destination}, {destination, source}} {
		contains, err := transferPhysicalAncestor(pair[0], pair[1])
		if err != nil {
			return "", "", err
		}
		if contains {
			return "", "", fmt.Errorf("streaming ledger transfer paths overlap")
		}
	}
	return source, destination, nil
}

func transferPhysicalAncestor(ancestor, child string) (bool, error) {
	info, err := os.Stat(ancestor)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for probe := child; ; probe = filepath.Dir(probe) {
		current, err := os.Stat(probe)
		if err == nil && os.SameFile(info, current) {
			return true, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		if filepath.Dir(probe) == probe {
			return false, nil
		}
	}
}
