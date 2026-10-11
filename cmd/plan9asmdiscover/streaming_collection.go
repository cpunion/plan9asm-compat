package main

import (
	"container/heap"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

// This is a manifest/identity inventory, never a per-run record list. Walking
// retains the reference collection's no-follow policy and sorted source order.
type transferSources struct {
	root     string
	identity os.FileInfo
	roots    []string
}

func captureTransferSources(root string) (*transferSources, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("streaming transfer source is not a directory")
	}
	sources := &transferSources{root: root, identity: info}
	if _, err := os.Stat(filepath.Join(root, "manifest.json")); err == nil {
		sources.roots = []string{root}
		return sources, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	err = filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "manifest.json" {
			sources.roots = append(sources.roots, filepath.Dir(name))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read transfer collection %q: %w", root, err)
	}
	if len(sources.roots) == 0 {
		return nil, fmt.Errorf("read transfer collection %q: no manifest.json found", root)
	}
	sort.Strings(sources.roots)
	return sources, nil
}

func (s *transferSources) verify() error {
	current, err := captureTransferSources(s.root)
	if err != nil {
		return fmt.Errorf("transfer source set changed: %w", err)
	}
	if !os.SameFile(s.identity, current.identity) || !reflect.DeepEqual(s.roots, current.roots) {
		return fmt.Errorf("transfer source set changed: %q", s.root)
	}
	return nil
}

func transferCollectionBucket(publisher *publicationShardWriter, oldPath string, paths []string) error {
	cursors := make([]*transferModuleCursor, 0, len(paths)+1)
	for _, name := range append([]string{oldPath}, paths...) {
		cursor, err := newTransferModuleCursor(name)
		if err != nil {
			return err
		}
		cursors = append(cursors, cursor)
	}
	return transferCursorModules(publisher, cursors)
}

// Only cursor metadata scales with the member count. One source group is read
// and closed at a time, then reduced in manifest order. Fold the sources first:
// @latest failures make that merge non-associative with the destination.
func transferCursorModules(publisher *publicationShardWriter, cursors []*transferModuleCursor) error {
	queue := &transferCursorHeap{cursors: cursors}
	for i, cursor := range cursors {
		if cursor.module != "" {
			queue.indexes = append(queue.indexes, i)
		}
	}
	heap.Init(queue)
	for queue.Len() > 0 {
		module := cursors[queue.indexes[0]].module
		var base, update discoveryReport
		for queue.Len() > 0 && cursors[queue.indexes[0]].module == module {
			index := heap.Pop(queue).(int)
			cursor := cursors[index]
			group, err := cursor.readGroup(false)
			if err != nil {
				return err
			}
			if index == 0 {
				base = group.report
			} else {
				update, err = mergeDiscoveryReports(update, group.report)
				if err != nil {
					return fmt.Errorf("merge transfer collection module: %w", err)
				}
			}
			if cursor.module != "" {
				heap.Push(queue, index)
			}
		}
		merged, err := mergeDiscoveryReports(base, update)
		if err != nil {
			return fmt.Errorf("merge transfer module: %w", err)
		}
		if err := publisher.emitModule(merged); err != nil {
			return err
		}
	}
	return publisher.finishShard()
}

// Ties use source ordinal, so heap scheduling preserves the exact left fold.
// Selecting a module is logarithmic, not a scan of all members for each module.
type transferCursorHeap struct {
	indexes []int
	cursors []*transferModuleCursor
}

func (q transferCursorHeap) Len() int { return len(q.indexes) }
func (q transferCursorHeap) Less(i, j int) bool {
	a, b := q.indexes[i], q.indexes[j]
	if q.cursors[a].module == q.cursors[b].module {
		return a < b
	}
	return q.cursors[a].module < q.cursors[b].module
}
func (q transferCursorHeap) Swap(i, j int)   { q.indexes[i], q.indexes[j] = q.indexes[j], q.indexes[i] }
func (q *transferCursorHeap) Push(value any) { q.indexes = append(q.indexes, value.(int)) }
func (q *transferCursorHeap) Pop() any {
	last := len(q.indexes) - 1
	value := q.indexes[last]
	q.indexes = q.indexes[:last]
	return value
}
