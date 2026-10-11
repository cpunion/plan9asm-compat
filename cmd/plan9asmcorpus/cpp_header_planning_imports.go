package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// Planning has its own original source role. Neither these bytes nor their
// references grant the later execution a generated-header or object outcome.
func discoveryPlanningImportedSources(header gotoolprofile.GeneratedHeaderProof, module string) (map[string]string, error) {
	if len(header.Imports) > 4096 {
		return nil, fmt.Errorf("planning query import graph exceeds its source bound")
	}
	wanted := make(map[string]string)
	for _, imported := range header.Imports {
		if imported.ModulePath != module {
			continue
		}
		for file, digest := range imported.GoSHA256 {
			if !ordinarySelectionLocalPath(file) || !strings.HasSuffix(file, ".go") ||
				!discoverySHA256Pattern.MatchString(digest) || len(wanted) >= 32768 {
				return nil, fmt.Errorf("planning imported original source has an unclosed identity")
			}
			if before := wanted[file]; before != "" && before != digest {
				return nil, fmt.Errorf("planning imports disagree on original source bytes")
			}
			wanted[file] = digest
		}
	}
	return wanted, nil
}

func captureDiscoveryPlanningImports(role *discoveryCPPHeaderPlanning, queryPlan *discoveryOrdinarySelectionPlan,
	header gotoolprofile.GeneratedHeaderProof, module, root string,
) (map[string]string, error) {
	wanted, err := discoveryPlanningImportedSources(header, module)
	if err != nil {
		return nil, err
	}
	if len(wanted) == 0 {
		return nil, nil // Preserve canonical omission through JSON projections.
	}
	if role.ImportedSources == nil {
		role.ImportedSources = make(map[string]string)
	}
	for file, digest := range wanted {
		if queryPlan.GeneratedGoSources[file] != digest {
			return nil, fmt.Errorf("planning imported source lacks actual original ZIP-bound query input")
		}
		name := filepath.Join(root, filepath.FromSlash(file))
		if err := discoveryCPPRegularSource(root, name); err != nil {
			return nil, err
		}
		data, err := readDiscoveryHeaderPlanningSource(name)
		if err != nil || discoveryFeatureBytesSHA256(data) != digest {
			return nil, fmt.Errorf("planning imported source differs from actual query input: %v", err)
		}
		if before, found := role.ImportedSources[file]; found && before != string(data) {
			return nil, fmt.Errorf("planning imported original source changed between queries")
		}
		role.ImportedSources[file] = string(data)
	}
	return wanted, nil
}

func replayDiscoveryPlanningImports(role *discoveryCPPHeaderPlanning, query *discoveryCPPHeaderPlanningQuery,
	module string,
) (map[string]string, error) {
	if query.Metadata == nil || len(query.Metadata.Headers) != 1 || len(query.ImportedGoSHA256) > 32768 {
		return nil, fmt.Errorf("planning import source role has no unique bounded compiler query")
	}
	wanted, err := discoveryPlanningImportedSources(query.Metadata.Headers[0], module)
	if err != nil {
		return nil, err
	}
	if len(wanted) != len(query.ImportedGoSHA256) {
		return nil, fmt.Errorf("planning query has missing or unconsumed original import references")
	}
	for file, digest := range wanted {
		text, found := role.ImportedSources[file]
		if !found || query.ImportedGoSHA256[file] != digest || discoveryFeatureBytesSHA256([]byte(text)) != digest {
			return nil, fmt.Errorf("planning query lost its complete original imported source role")
		}
	}
	return wanted, nil
}
