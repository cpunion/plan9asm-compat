package main

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func discoveryCPPOriginalConsumerInput(inputs *discoveryCPPInputs) (*gotoolprofile.ConsumerInput, error) {
	input, err := discoveryCPPOriginalConsumerQuery(inputs)
	if err != nil {
		return nil, err
	}
	return input, gotoolprofile.ValidateCPPOriginalInputs(input)
}

// A query owns fresh transport maps, not source authority. Direct consumers
// validate through the wrapper above; replay validates the complete graph in
// ReplayCPPOriginal before execution. Never reuse a prior validation receipt.
func discoveryCPPOriginalConsumerQuery(inputs *discoveryCPPInputs) (*gotoolprofile.ConsumerInput, error) {
	if inputs == nil || inputs.Protocol != discoveryReplayCPPInputsProtocol {
		return nil, fmt.Errorf("missing full original CPP graph")
	}
	input := &gotoolprofile.ConsumerInput{
		CPPSourceProtocol: gotoolprofile.CPPOriginalReplayProtocol,
		Sources:           make(map[string]string), ToolSources: make(map[string]string),
		CPPOriginals: &gotoolprofile.CPPOriginalReplayInput{
			Sources: make(map[string]string), Units: make(map[string]gotoolprofile.CPPOriginalUnit),
			RequiredExpandedOperands: make(map[string][]gotoolprofile.CPPPackageSearchMiss),
		},
	}
	// Register each source once per construction, not once per unit. Captured
	// originals may reuse the parser's private immutable lexer index; every
	// consumer still owns new maps and validates the complete original bytes.
	// The query only needs the exact include spelling. Keep the full typed
	// lexer resource in its source index, rather than copying it into this map.
	resources := make(map[string]string)
	for id, source := range inputs.Sources {
		if source.Original == nil {
			return nil, fmt.Errorf("CPP consumer omitted original source bytes")
		}
		origin, file, err := discoveryCPPSourceIdentity(id)
		if err != nil {
			return nil, err
		}
		registered, err := discoveryCPPRegisteredResources(inputs, source)
		if err != nil {
			return nil, err
		}
		for _, resource := range registered {
			resources[id+resource.key] = resource.directive.Include
		}
		input.CPPOriginals.Sources[id] = *source.Original
		if origin == "tool" {
			input.ToolSources[file] = source.SHA256
		} else {
			input.Sources[file] = source.SHA256
		}
	}
	for _, unit := range inputs.Units {
		input.AsmFiles = append(input.AsmFiles, unit.File)
		registered := gotoolprofile.CPPOriginalUnit{Includes: make(map[string]string)}
		for key, target := range unit.Includes {
			include, found := resources[key]
			if !found || target == "" {
				return nil, fmt.Errorf("CPP include has an unregistered or empty original resource edge: %s", key)
			}
			if previous := registered.Includes[include]; previous != "" && previous != target {
				return nil, fmt.Errorf("CPP fixed include origins conflict between raw controls")
			}
			registered.Includes[include] = target
		}
		for key, kind := range unit.DeferredIncludes {
			if _, found := resources[key]; !found {
				return nil, fmt.Errorf("CPP deferred include has an unregistered original resource edge: %s", key)
			}
			if _, bound := unit.Includes[key]; bound {
				return nil, fmt.Errorf("CPP original resource has both bound and deferred roles: %s", key)
			}
			switch kind {
			case "generated_go_asm":
				registered.GeneratedHeaders = []string{"go_asm.h"}
			case "unresolved_include", "unresolved_candidate":
				// Registered candidates do not become active include grants.
			default:
				return nil, fmt.Errorf("CPP original resource has an unknown deferred role: %s", key)
			}
		}
		input.CPPOriginals.Units[unit.File] = registered
	}
	input.CPPIncludeSearchMisses = discoveryCPPPhysicalSearchMisses(inputs)
	return input, nil
}

func bindDiscoveryCPPOriginalConsumer(input *gotoolprofile.ConsumerInput, inputs *discoveryCPPInputs) {
	graphInput, err := discoveryCPPOriginalConsumerInput(inputs)
	input.CPPSourceProtocol = gotoolprofile.CPPOriginalReplayProtocol
	if err != nil {
		return // The mandatory protocol without a graph is fail-closed.
	}
	if err := projectDiscoveryCPPOriginalPackage(input, graphInput.CPPOriginals); err != nil {
		return
	}
	input.CPPOriginals = graphInput.CPPOriginals
	defines, err := plan9asm.GoAssemblerDefinesForEnvironment(input.Observed.Environment["GOOS"], input.Observed.Environment["GOARCH"], input.Observed.Environment)
	if err != nil {
		return
	}
	for _, assembly := range input.AsmFiles {
		packagePath := gotoolprofile.CPPOriginalPackagePath(input.Module, assembly)
		var header []byte
		if input.GeneratedHeaders != nil {
			for _, actual := range input.GeneratedHeaders.Headers {
				if actual.PackagePath == packagePath {
					header, err = gotoolprofile.CanonicalGeneratedHeader(actual.Definitions)
					if err != nil {
						return
					}
				}
			}
		}
		_, _, required, err := gotoolprofile.ReplayCPPOriginal(input, assembly, packagePath, defines, header)
		if err != nil {
			continue // Query inputs cannot manufacture a missing native header.
		}
		input.CPPOriginals.RequiredExpandedOperands[assembly] = required
		input.CPPIncludeSearchMisses = append(input.CPPIncludeSearchMisses, required...)
	}
	gotoolprofile.SortCPPIncludeSearch(input.CPPIncludeSearchMisses)
}

// Only original bodies are projected. The invocation still retains complete
// module membership, source hashes, selection headers and physical search
// witnesses. Registration includes selected source-only siblings; the actual
// Go package consumer independently checks that full set before translation.
func projectDiscoveryCPPOriginalPackage(input *gotoolprofile.ConsumerInput, graph *gotoolprofile.CPPOriginalReplayInput) error {
	units := make(map[string]bool)
	for _, files := range [][]string{input.AsmFiles, input.RegisteredAsmFiles} {
		for _, file := range files {
			units[file] = true
		}
	}
	if len(units) == 0 {
		return fmt.Errorf("CPP package projection lacks selected assembly")
	}
	sources := make(map[string]bool)
	for file := range units {
		unit, exists := graph.Units[file]
		if !exists {
			return fmt.Errorf("CPP package projection omitted selected original: %s", file)
		}
		sources["module/"+file] = true
		// Includes registers all transitive raw edges, including inactive
		// alternatives. Projection is not an active-branch pruning policy.
		for _, source := range unit.Includes {
			sources[source] = true
		}
	}
	for source := range sources {
		if _, exists := graph.Sources[source]; !exists {
			return fmt.Errorf("CPP package projection omitted original include: %s", source)
		}
	}
	// The query constructed these maps afresh. Never delete from the captured
	// module graph, reuse a prior query or mutate its immutable original text.
	for file := range graph.Units {
		if !units[file] {
			delete(graph.Units, file)
		}
	}
	for source := range graph.Sources {
		if !sources[source] {
			delete(graph.Sources, source)
		}
	}
	return nil
}

func discoveryCPPPhysicalSearchMisses(inputs *discoveryCPPInputs) []gotoolprofile.CPPPackageSearchMiss {
	var misses []gotoolprofile.CPPPackageSearchMiss
	seen := make(map[string]bool)
	for _, unit := range inputs.Units {
		for _, miss := range unit.PackageSearchMisses {
			if miss.Protocol != gotoolprofile.CPPPackageSearchMissProtocol {
				continue // Raw generated resources are not active receipts.
			}
			key := strings.Join([]string{miss.Assembly, miss.Source, miss.Include}, "\x00")
			if !seen[key] {
				seen[key] = true
				misses = append(misses, miss)
			}
		}
	}
	gotoolprofile.SortCPPIncludeSearch(misses)
	return misses
}
