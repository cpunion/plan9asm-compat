package main

import (
	"fmt"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// The ordinary source plan already authenticates every root directory member
// against the original ZIP. Keep that exact identity: only complete original
// go.mod can derive an instrumentation namespace distinct from its archive.
func discoveryInstrumentationModulePath(plan *discoveryOrdinarySelectionPlan) (string, error) {
	if plan == nil || plan.InstrumentationPlan == nil {
		return "", fmt.Errorf("instrumentation namespace lacks its original source plan")
	}
	metadata := plan.InstrumentationPlan.ModuleMetadata
	if metadata == "" {
		return plan.Module, nil
	}
	if plan.ProxyGoMod != nil {
		return "", fmt.Errorf("instrumentation archive alias cannot use proxy metadata")
	}
	digest := ""
	for _, directory := range plan.Directories {
		if directory.Directory != "." {
			continue
		}
		for _, entry := range directory.Entries {
			if entry.Name == "go.mod" && entry.Kind == "file" {
				if digest != "" {
					return "", fmt.Errorf("instrumentation alias has duplicate original module metadata")
				}
				digest = entry.SHA256
			}
		}
	}
	declared, err := gotoolprofile.InstrumentationOriginalModulePath(metadata, digest)
	if err != nil || declared == plan.Module {
		return "", fmt.Errorf("instrumentation alias differs from its original ZIP declaration: %v", err)
	}
	return declared, nil
}

func captureDiscoveryInstrumentationNamespace(plan *discoveryOrdinarySelectionPlan, root string) error {
	if plan == nil || plan.InstrumentationPlan == nil || plan.InstrumentationPlan.ModuleMetadata != "" {
		return fmt.Errorf("instrumentation namespace capture requires a fresh original source plan")
	}
	if plan.ProxyGoMod != nil {
		return nil // Existing signed legacy role remains exact, never an alias.
	}
	filename := filepath.Join(root, "go.mod")
	if err := discoveryCPPRegularSource(root, filename); err != nil {
		return err
	}
	data, err := readDiscoveryChecksumFile(filename, 2<<20)
	if err != nil {
		return err
	}
	declared, err := parseDeclaredModulePath(data)
	if err != nil {
		return err
	}
	if declared != plan.Module {
		copy, mode := *plan, *plan.InstrumentationPlan
		mode.ModuleMetadata = string(data)
		copy.InstrumentationPlan = &mode
		if _, err := discoveryInstrumentationModulePath(&copy); err != nil {
			return err
		}
		plan.InstrumentationPlan.ModuleMetadata = mode.ModuleMetadata
	}
	return err
}
