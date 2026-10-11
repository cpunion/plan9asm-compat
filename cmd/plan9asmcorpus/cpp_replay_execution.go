package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// Replay full originals with the same executor as the actual CLI. Resource
// registration includes inactive edges; only this execution decides active
// inputs, branches and output. Defines retain their exact ordered -D text.
func replayDiscoveryOriginalCPP(inputs *discoveryCPPInputs, unit discoveryCPPUnit, header *gotoolprofile.GeneratedHeaderProof, defines []string) (plan9asm.AssemblyCPPObservation, map[string]string, error) {
	return replayDiscoveryOriginalCPPWithIndex(inputs, unit, header, defines, nil)
}

func replayDiscoveryOriginalCPPWithIndex(inputs *discoveryCPPInputs, unit discoveryCPPUnit,
	header *gotoolprofile.GeneratedHeaderProof, defines []string, sourceIndex *discoveryCPPPlanningSourceIndex) (plan9asm.AssemblyCPPObservation, map[string]string, error) {
	if inputs == nil || inputs.Protocol != discoveryReplayCPPInputsProtocol {
		return plan9asm.AssemblyCPPObservation{}, nil, fmt.Errorf("missing full original CPP replay protocol")
	}
	if sourceIndex != nil {
		var err error
		inputs, err = indexDiscoveryReplayCPPSources(inputs, sourceIndex)
		if err != nil {
			return plan9asm.AssemblyCPPObservation{}, nil, err
		}
	}
	// The public replay executor performs mandatory whole-graph validation.
	// Construct fresh inputs without hashing the same complete originals twice.
	input, err := discoveryCPPOriginalConsumerQuery(inputs)
	if err != nil {
		return plan9asm.AssemblyCPPObservation{}, nil, err
	}
	var data []byte
	packagePath := ""
	if header != nil {
		packagePath = header.PackagePath
		data, err = gotoolprofile.CanonicalGeneratedHeader(header.Definitions)
		if err != nil {
			return plan9asm.AssemblyCPPObservation{}, nil, err
		}
	}
	observation, used, _, err := gotoolprofile.ReplayCPPOriginal(input, unit.File, packagePath, defines, data)
	if err != nil {
		return plan9asm.AssemblyCPPObservation{}, nil, err
	}
	return observation, used, nil
}

func discoveryReplaySearchMisses(unit discoveryCPPUnit) []gotoolprofile.CPPPackageSearchMiss {
	var misses []gotoolprofile.CPPPackageSearchMiss
	for _, miss := range unit.PackageSearchMisses {
		misses = append(misses, miss)
	}
	gotoolprofile.SortCPPIncludeSearch(misses)
	return misses
}

func validateDiscoveryOriginalCPPConsumption(inputs *discoveryCPPInputs, unit discoveryCPPUnit, header *gotoolprofile.GeneratedHeaderProof, defines []string, proof gotoolprofile.CPPProof) error {
	observation, used, err := replayDiscoveryOriginalCPP(inputs, unit, header, defines)
	if err != nil || !reflect.DeepEqual(used, proof.Inputs) || discoveryFeatureBytesSHA256([]byte(observation.Output)) != proof.ExpandedSHA256 {
		return fmt.Errorf("actual CPP inputs/output differ from full original source replay: %s: %v", unit.File, err)
	}
	return nil
}

// Identity is source/expansion lineage, not a profile-dependent event ordinal.
// Both branch sides of the same invocation receive the same key. Payloads
// distinguish repeated generated controls and definition versions.
func discoveryCPPBranchCoverage(observation plan9asm.AssemblyCPPObservation) (map[string]bool, error) {
	events := make(map[int]plan9asm.AssemblyCPPEvent, len(observation.Events))
	for _, event := range observation.Events {
		events[event.Ordinal] = event
	}
	var identity func(int, int) (string, error)
	identity = func(ordinal, depth int) (string, error) {
		if ordinal == 0 {
			return "", nil
		}
		event, found := events[ordinal]
		if !found || depth > 32 {
			return "", fmt.Errorf("CPP branch has missing/unbounded expansion lineage")
		}
		parent, err := identity(event.Expansion, depth+1)
		if err != nil {
			return "", err
		}
		include, err := identity(event.Include, depth+1)
		if err != nil {
			return "", err
		}
		definition, err := identity(event.Definition, depth+1)
		if err != nil {
			return "", err
		}
		data, err := json.Marshal(struct {
			Position                                           plan9asm.AssemblyCPPObservedPosition
			Kind, Name, Directive, Parent, Include, Definition string
			Tokens                                             []plan9asm.AssemblyCPPObservedToken
		}{event.Position, event.Kind, event.Name, event.Directive, parent, include, definition, event.Tokens})
		return string(data), err
	}
	result := make(map[string]bool)
	for _, event := range observation.Events {
		if event.Kind != "control" || event.Directive != "ifdef" && event.Directive != "ifndef" || !event.EnabledBefore {
			continue
		}
		key, err := identity(event.Ordinal, 0)
		if err != nil {
			return nil, err
		}
		result[key+"/"+strconv.FormatBool(event.EnabledAfter)] = true
	}
	return result, nil
}
