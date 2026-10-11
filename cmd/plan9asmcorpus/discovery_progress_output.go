package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type preparedDiscoveryProgress struct {
	destination string
	temporary   string
	owned       os.FileInfo
	parent      os.FileInfo
	digest      string
}

// A narrow first-party publication helper. Production verification uses the
// preparation API so its final input checks precede publication.
func writeDiscoveryProgressOutput(filename string, progress discoveryProgress) (result error) {
	prepared, err := prepareDiscoveryProgressOutput(filename, progress)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, prepared.discard()) }()
	return prepared.publish()
}

// Prepare and close the complete diagnostic before the final input checks.
// Preparation is not publication and does not create the destination file.
func prepareDiscoveryProgressOutput(filename string, progress discoveryProgress) (*preparedDiscoveryProgress, error) {
	if !filepath.IsAbs(filename) || filepath.Base(filename) != "assembly-progress.json" {
		return nil, fmt.Errorf("discovery progress output requires an absolute new assembly-progress.json path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(parent, ".assembly-progress-*")
	if err != nil {
		return nil, err
	}
	owned, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	prepared := &preparedDiscoveryProgress{
		destination: filepath.Join(parent, filepath.Base(filename)), temporary: file.Name(),
		owned: owned, parent: parentInfo,
	}
	digest := sha256.New()
	encoder := json.NewEncoder(io.MultiWriter(file, digest))
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(progress)
	written, statErr := file.Stat()
	if err := errors.Join(writeErr, statErr, file.Close()); err != nil {
		return nil, errors.Join(err, prepared.discard())
	}
	prepared.owned = written
	prepared.digest = fmt.Sprintf("%x", digest.Sum(nil))
	return prepared, nil
}

// Link only after all frozen input checks succeed. Existing output is never
// replaced, including a file that appeared after the initial preflight.
func (prepared *preparedDiscoveryProgress) publish() error {
	physicalParent, err := filepath.EvalSymlinks(filepath.Dir(prepared.destination))
	if err != nil || physicalParent != filepath.Dir(prepared.destination) {
		return errors.Join(fmt.Errorf("progress destination parent alias changed"), err)
	}
	parent, err := os.Stat(filepath.Dir(prepared.destination))
	if err != nil || !os.SameFile(prepared.parent, parent) {
		return errors.Join(fmt.Errorf("progress destination parent changed"), err)
	}
	if err := prepared.verifyBytes(prepared.temporary); err != nil {
		return err
	}
	if err := os.Link(prepared.temporary, prepared.destination); err != nil {
		return err
	}
	return prepared.verifyBytes(prepared.destination)
}

func (prepared *preparedDiscoveryProgress) verifyBytes(filename string) error {
	actual, err := os.Lstat(filename)
	if err != nil || !sameDiscoveryPhysicalMember(prepared.owned, actual) {
		return errors.Join(fmt.Errorf("owned progress file changed"), err)
	}
	digest := sha256.New()
	if err := hashDiscoveryPhysicalFile(filename, prepared.owned, digest); err != nil {
		return err
	}
	if fmt.Sprintf("%x", digest.Sum(nil)) != prepared.digest {
		return fmt.Errorf("owned progress file changed while reading")
	}
	return nil
}

// Never remove a replacement supplied by another operation. This method runs
// on every ordinary error path before main's strict exit, not in an os.Exit defer.
func (prepared *preparedDiscoveryProgress) discard() error {
	actual, err := os.Lstat(prepared.temporary)
	if err != nil || !os.SameFile(prepared.owned, actual) {
		return errors.Join(fmt.Errorf("owned progress temporary file changed"), err)
	}
	return os.Remove(prepared.temporary)
}
