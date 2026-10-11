package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

type discoveryPhysicalMember struct {
	name string
	info os.FileInfo
}

// Only the filesystem inventory is retained. Record bytes are streamed into
// the digest, never decoded or kept as another in-memory ledger.
type discoveryPhysicalSnapshot struct {
	root    string
	digest  string
	members []discoveryPhysicalMember
}

func collectDiscoveryPhysicalSnapshot(directory string) (discoveryPhysicalSnapshot, error) {
	var snapshot discoveryPhysicalSnapshot
	root, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return snapshot, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return snapshot, err
	}
	snapshot.root = root
	digest := sha256.New()
	err = filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular physical ledger member")
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		snapshot.members = append(snapshot.members, discoveryPhysicalMember{relative, info})
		fmt.Fprintf(digest, "%q:%d:%d:", filepath.ToSlash(relative), info.Mode(), info.Size())
		if info.IsDir() {
			return nil
		}
		return hashDiscoveryPhysicalFile(name, info, digest)
	})
	if err != nil {
		return discoveryPhysicalSnapshot{}, err
	}
	finalRoot, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return discoveryPhysicalSnapshot{}, err
	}
	finalRoot, err = filepath.Abs(finalRoot)
	if err != nil || finalRoot != root {
		return discoveryPhysicalSnapshot{}, errors.Join(fmt.Errorf("physical ledger root changed while reading"), err)
	}
	for _, member := range snapshot.members {
		final, err := os.Lstat(filepath.Join(root, member.name))
		if err != nil || !sameDiscoveryPhysicalMember(member.info, final) {
			return discoveryPhysicalSnapshot{}, errors.Join(fmt.Errorf("physical ledger inventory changed while reading"), err)
		}
	}
	snapshot.digest = fmt.Sprintf("%x", digest.Sum(nil))
	return snapshot, nil
}

func hashDiscoveryPhysicalFile(name string, expected os.FileInfo, digest io.Writer) error {
	if expected.Size() < 0 || expected.Size() == math.MaxInt64 {
		return fmt.Errorf("physical file requires a bounded observable extent")
	}
	physical, err := filepath.EvalSymlinks(name)
	if err != nil {
		return err
	}
	file, err := openDiscoveryReport(name)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !sameDiscoveryPhysicalMember(expected, opened) {
		return errors.Join(fmt.Errorf("physical file changed while opening"), statErr, file.Close())
	}
	// The extra byte detects growth without consuming an arbitrarily growing
	// input before eventually noticing the size or metadata mismatch.
	n, readErr := io.Copy(digest, io.LimitReader(file, expected.Size()+1))
	final, statErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(readErr, statErr, closeErr); err != nil {
		return err
	}
	if n != expected.Size() || !sameDiscoveryPhysicalMember(expected, final) {
		return fmt.Errorf("physical file changed while reading")
	}
	pathname, err := os.Lstat(name)
	if err != nil || !sameDiscoveryPhysicalMember(expected, pathname) {
		return errors.Join(fmt.Errorf("physical file pathname changed while reading"), err)
	}
	finalPhysical, err := filepath.EvalSymlinks(name)
	if err != nil || finalPhysical != physical {
		return errors.Join(fmt.Errorf("physical file path alias changed while reading"), err)
	}
	return nil
}

func sameDiscoveryPhysicalMember(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Mode() == after.Mode() &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func verifyDiscoveryPhysicalSnapshot(directory string, before discoveryPhysicalSnapshot) error {
	after, err := collectDiscoveryPhysicalSnapshot(directory)
	if err != nil {
		return fmt.Errorf("committed assembly ledger changed: %w", err)
	}
	if before.root != after.root || before.digest != after.digest || len(before.members) != len(after.members) {
		return fmt.Errorf("committed assembly ledger changed while verifying reports")
	}
	for index, member := range before.members {
		if member.name != after.members[index].name || !sameDiscoveryPhysicalMember(member.info, after.members[index].info) {
			return fmt.Errorf("committed assembly ledger changed while verifying reports")
		}
	}
	return nil
}

func verifyDiscoveryAggregateInputs(root, scan, stored string, source discoverySourceIdentity,
	scanSHA string, storedSnapshot discoveryPhysicalSnapshot) error {
	finalSource, err := collectDiscoverySource(root)
	if err != nil {
		return err
	}
	if finalSource != source {
		return fmt.Errorf("discovery source changed while verifying reports")
	}
	finalScanSHA, err := discoveryLedgerFingerprint(scan)
	if err != nil {
		return err
	}
	if finalScanSHA != scanSHA {
		return fmt.Errorf("discovery ledger changed while verifying reports")
	}
	if stored != "" {
		return verifyDiscoveryPhysicalSnapshot(stored, storedSnapshot)
	}
	return nil
}
