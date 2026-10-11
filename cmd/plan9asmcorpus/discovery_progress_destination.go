package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Resolve existing path components before interpreting their successors. This
// preserves physical symlink/.. semantics, even when the final directories do
// not exist yet. Preflight itself never creates a directory or output file.
func canonicalDiscoveryProgressPath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("discovery progress destination requires a path")
	}
	name = filepath.FromSlash(name)
	if !filepath.IsAbs(name) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		name = cwd + string(filepath.Separator) + name
	}
	volume := filepath.VolumeName(name)
	resolved := volume + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(name, volume), string(filepath.Separator))
	for index, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		parent := resolved
		resolved = filepath.Join(resolved, part)
		info, err := os.Lstat(resolved)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		actualName, err := physicalDiscoveryProgressEntry(parent, part, info)
		if err != nil {
			return "", err
		}
		resolved = filepath.Join(parent, actualName)
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err = filepath.EvalSymlinks(resolved)
			if err != nil {
				return "", err
			}
			resolved, err = canonicalDiscoveryProgressPath(resolved)
			if err != nil {
				return "", err
			}
			info, err = os.Stat(resolved)
			if err != nil {
				return "", err
			}
		}
		if !info.IsDir() && index != len(parts)-1 {
			return "", fmt.Errorf("discovery progress directory component is not a directory")
		}
	}
	return resolved, nil
}

// A successful Stat may accept a different case, Unicode or short-name alias
// on the current filesystem. Recover the actual existing entry by identity,
// not by case folding: genuinely distinct names on a sensitive filesystem
// must remain distinct. The exact spelling is the common fast path.
func physicalDiscoveryProgressEntry(parent, requested string, observed os.FileInfo) (string, error) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.Name() != requested {
			continue
		}
		actual, err := entry.Info()
		if err != nil || !os.SameFile(observed, actual) {
			return "", fmt.Errorf("discovery progress path changed during canonical preflight: %v", err)
		}
		return entry.Name(), nil
	}
	for _, entry := range entries {
		actual, err := entry.Info()
		if err == nil && os.SameFile(observed, actual) {
			return entry.Name(), nil
		}
	}
	return "", fmt.Errorf("discovery progress physical entry changed during canonical preflight")
}

func discoveryPathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateDiscoveryProgressDirectory(root, scan, stored, output string) (string, error) {
	physicalRoot, err := canonicalDiscoveryProgressPath(root)
	if err != nil {
		return "", err
	}
	rootInfo, err := os.Stat(physicalRoot)
	if err != nil || !rootInfo.IsDir() {
		return "", fmt.Errorf("discovery progress preflight requires an existing repository root: %v", err)
	}
	physicalOutput, err := canonicalDiscoveryProgressPath(output)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(physicalOutput); err == nil && !info.IsDir() {
		return "", fmt.Errorf("discovery progress destination is not a directory")
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	for _, input := range []string{scan, stored} {
		if input == "" {
			continue
		}
		physicalInput, err := canonicalDiscoveryProgressPath(input)
		if err != nil {
			return "", err
		}
		if discoveryPathContains(physicalInput, physicalOutput) || discoveryPathContains(physicalOutput, physicalInput) {
			return "", fmt.Errorf("discovery progress destination overlaps an input ledger")
		}
	}
	if discoveryPathContains(physicalRoot, physicalOutput) {
		ignored := filepath.Join(physicalRoot, "_out")
		if !discoveryPathContains(ignored, physicalOutput) {
			return "", fmt.Errorf("repository discovery progress output requires ignored _out storage")
		}
		for _, name := range []string{"scan-status.json", "assembly-progress.json"} {
			relative, err := filepath.Rel(physicalRoot, filepath.Join(physicalOutput, name))
			if err != nil {
				return "", err
			}
			cmd := exec.Command("git", "-C", physicalRoot, "check-ignore", "--quiet", "--", filepath.ToSlash(relative))
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("repository discovery progress output requires ignored _out storage: %w", err)
			}
		}
	}
	return physicalOutput, nil
}
