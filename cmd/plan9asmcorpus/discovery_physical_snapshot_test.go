package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type mutatingPhysicalDigest struct {
	digest io.Writer
	mutate func() error
	bytes  int64
}

func (writer *mutatingPhysicalDigest) Write(data []byte) (int, error) {
	if writer.mutate != nil {
		mutate := writer.mutate
		writer.mutate = nil
		if err := mutate(); err != nil {
			return 0, err
		}
	}
	n, err := writer.digest.Write(data)
	writer.bytes += int64(n)
	return n, err
}

func TestDiscoveryPhysicalReadRejectsActualGrowthAndReplacement(t *testing.T) {
	for _, kind := range []string{"growth", "same-byte replacement"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			filename := filepath.Join(parent, "record.jsonl")
			original := bytes.Repeat([]byte("x"), 64*1024)
			if err := os.WriteFile(filename, original, 0600); err != nil {
				t.Fatal(err)
			}
			expected, err := os.Lstat(filename)
			if err != nil {
				t.Fatal(err)
			}
			mutations := 0
			writer := &mutatingPhysicalDigest{digest: sha256.New(), mutate: func() error {
				mutations++
				if kind == "growth" {
					file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0)
					if err != nil {
						return err
					}
					_, writeErr := file.Write(bytes.Repeat([]byte("y"), 2*1024*1024))
					closeErr := file.Close()
					if writeErr != nil {
						return writeErr
					}
					return closeErr
				}
				if err := os.Rename(filename, filepath.Join(parent, "original-record")); err != nil {
					return err
				}
				if err := os.WriteFile(filename, original, expected.Mode()); err != nil {
					return err
				}
				return os.Chtimes(filename, expected.ModTime(), expected.ModTime())
			}}
			err = hashDiscoveryPhysicalFile(filename, expected, writer)
			if mutations != 1 {
				t.Fatalf("real mutation not observed: %d", mutations)
			}
			if err == nil {
				t.Fatal("same-byte replaced pathname accepted from the old open inode")
			}
			if writer.bytes > expected.Size()+1 {
				t.Fatalf("growth consumed %d bytes beyond original extent+1 %d", writer.bytes, expected.Size()+1)
			}
			if kind == "same-byte replacement" {
				actual, statErr := os.Stat(filename)
				data, readErr := os.ReadFile(filename)
				if statErr != nil || readErr != nil || os.SameFile(expected, actual) || !bytes.Equal(original, data) {
					t.Fatalf("replacement preconditions lost: %v %v", statErr, readErr)
				}
			}
		})
	}
}

func TestDiscoveryPhysicalSnapshotInventoryAndIdentity(t *testing.T) {
	for _, kind := range []string{"unchanged", "bytes", "same-byte inode", "extra file", "missing file", "directory alias"} {
		t.Run(kind, func(t *testing.T) {
			container := t.TempDir()
			root := filepath.Join(container, "assembly-ledger")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(root, "manifest.json")
			writeTestFile(t, filename, "{}\n")
			snapshot, err := collectDiscoveryPhysicalSnapshot(root)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "bytes":
				writeTestFile(t, filename, "[]\n")
			case "same-byte inode":
				if err := os.Rename(filename, filepath.Join(container, "original-manifest")); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filename, "{}\n")
			case "extra file":
				writeTestFile(t, filepath.Join(root, "new.json"), "{}\n")
			case "missing file":
				if err := os.Remove(filename); err != nil {
					t.Fatal(err)
				}
			case "directory alias":
				old := filepath.Join(container, "original-root")
				if err := os.Rename(root, old); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(old, root); err != nil {
					t.Fatal(err)
				}
			}
			err = verifyDiscoveryPhysicalSnapshot(root, snapshot)
			if (err == nil) != (kind == "unchanged") {
				t.Fatal(fmt.Sprintf("%s physical snapshot: %v", kind, err))
			}
		})
	}
}
