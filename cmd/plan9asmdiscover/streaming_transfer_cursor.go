package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// No open descriptor, JSON buffer, AsmFiles or error payload survives a read.
// Offset/line/order metadata let the next read seek directly to its module;
// a boundary record is decoded twice, never a rewind of an earlier module.
type transferModuleCursor struct {
	path     string
	module   string
	offset   int64
	line     int
	previous shardedRecord // only Module/Version/Kind, never record payload
	identity os.FileInfo
}

func newTransferModuleCursor(path string) (*transferModuleCursor, error) {
	cursor := &transferModuleCursor{path: path}
	if path != "" {
		if _, err := cursor.readGroup(true); err != nil {
			return nil, err
		}
	}
	return cursor, nil
}

func (c *transferModuleCursor) readGroup(peek bool) (group transferModuleGroup, returnErr error) {
	file, err := os.Open(c.path)
	if err != nil {
		return group, fmt.Errorf("open transfer cursor %q: %w", c.path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close transfer cursor %q: %w", c.path, err))
		}
	}()
	identity, err := file.Stat()
	if err != nil {
		return group, err
	}
	if c.identity == nil {
		c.identity = identity
	} else if !os.SameFile(c.identity, identity) || c.identity.Size() != identity.Size() ||
		c.identity.Mode() != identity.Mode() || !c.identity.ModTime().Equal(identity.ModTime()) {
		return group, fmt.Errorf("transfer cursor input changed: %q", c.path)
	}
	if _, err := file.Seek(c.offset, io.SeekStart); err != nil {
		return group, err
	}
	position := c.offset
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		advance, token, err := bufio.ScanLines(data, atEOF)
		position += int64(advance)
		return advance, token, err
	})
	line, previous := c.line, c.previous
	bucket, err := strconv.ParseUint(filepath.Base(c.path)[:2], 16, 8)
	if err != nil {
		return group, err
	}
	var provisional ledgerSummary
	for {
		start := position
		if !scanner.Scan() {
			break
		}
		line++
		item, err := decodeRecordShardLine(c.path, byte(bucket), line, previous, scanner.Bytes(), &provisional)
		if err != nil {
			return group, err
		}
		if peek {
			c.module = item.Module
			return group, nil
		}
		if item.Module != c.module {
			if group.module == "" {
				return group, fmt.Errorf("transfer cursor module changed: %q", c.path)
			}
			c.module, c.offset, c.line, c.previous = item.Module, start, line-1, previous
			return group, nil
		}
		group.module = item.Module
		if err := appendPublicationRecord(&group.report, item); err != nil {
			return group, err
		}
		previous = shardedRecord{Module: item.Module, Version: item.Version, Kind: item.Kind}
	}
	if err := scanner.Err(); err != nil {
		return group, fmt.Errorf("read record shard %q: %w", c.path, err)
	}
	c.module, c.offset, c.line, c.previous = "", position, line, previous
	return group, nil
}
