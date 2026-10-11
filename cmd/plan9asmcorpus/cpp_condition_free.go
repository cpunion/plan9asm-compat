package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// This is a fresh query over complete inputs, not a cached source/header proof.
// It only establishes that ordinary CPP branch coverage cannot grow. The real
// baseline header query and all Go source-pair/profile consumers remain required.
func discoveryCPPConditionFree(plan *discoveryOrdinarySelectionPlan, unit discoveryCPPUnit,
	header *gotoolprofile.GeneratedHeaderProof, contexts ...context.Context) (bool, error) {
	return discoveryCPPConditionFreeWithIndex(plan, unit, header, nil, contexts...)
}

func discoveryCPPConditionFreeWithIndex(plan *discoveryOrdinarySelectionPlan, unit discoveryCPPUnit,
	header *gotoolprofile.GeneratedHeaderProof, sourceIndex *discoveryCPPPlanningSourceIndex,
	contexts ...context.Context) (bool, error) {
	if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
		return false, err
	}
	if plan == nil || plan.CPPInputs == nil {
		return false, fmt.Errorf("condition-free query omitted complete CPP inputs")
	}
	inputs, err := validatedDiscoveryReplayCPPInputsWithIndex(plan.CPPInputs, plan, []string{unit.File}, sourceIndex)
	if err != nil {
		return false, err
	}
	used := make(map[string]bool)
	if _, err := discoveryCPPUnitDirectives(inputs, unit, used); err != nil {
		return false, err
	}
	needsHeader := false
	for _, role := range unit.DeferredIncludes {
		if role != "generated_go_asm" {
			return false, nil
		}
		needsHeader = true
	}
	for _, id := range sortedDiscoverySet(used) {
		if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
			return false, err
		}
		source := inputs.Sources[id]
		if source.Original == nil {
			return false, fmt.Errorf("condition-free query omitted complete CPP original")
		}
		if !sourceIndex.conditionFreeText(*source.Original, id) {
			return false, nil
		}
	}
	if needsHeader {
		// Only cover's existing exact actual-source query supplies this input.
		// Public definitions or formatting never create a native header role.
		if header == nil {
			return false, nil
		}
		canonical, err := gotoolprofile.CanonicalGeneratedHeader(header.Definitions)
		if err != nil {
			return false, err
		}
		if !sourceIndex.conditionFreeText(string(canonical), "<observed-go_asm.h>") {
			return false, nil
		}
	}
	if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
		return false, err
	}
	return true, nil
}

func discoveryCPPConditionFreeText(text, file string) bool {
	inventory, err := plan9asm.InspectAssemblyCPPSource(text, file, nil)
	if err != nil || inventory.EOF.Kind != "eof" || inventory.EOF.End != len(text) {
		return false
	}
	for _, record := range inventory.Records {
		if record.Kind != "directive" || len(record.Tokens) < 2 {
			return false
		}
		switch record.Tokens[1].Text {
		case "define":
			if record.Definition == nil {
				return false
			}
			for _, token := range record.Definition.Replacement {
				if token.Text == "#" {
					return false
				}
			}
		case "include":
			if len(record.Tokens) != 4 || record.Tokens[2].Kind != "string" ||
				record.Tokens[3].Kind != "newline" && record.Tokens[3].Kind != "eof" {
				return false
			}
		case "undef":
		default:
			return false // Includes inactive conditionals, #line and lexical controls.
		}
	}
	// Reuse the exact shared reader's complete token query, including ordinary
	// operands which the compact directive inventory intentionally omits. Its
	// existing smaller 1 MiB/1M-token bound is not raised: larger/unknown inputs
	// simply retain the original all-CPU planning path. The synthetic key is only
	// a lexical query wrapper; it is never a -D command or source admission.
	const key = "__plan9asm_condition_free="
	if len(text) > 1<<20-len(key) {
		return false
	}
	query, err := plan9asm.InspectAssemblyCPPDriverDefinitions([]string{key + text})
	if err != nil || len(query) != 1 {
		return false
	}
	for _, token := range query[0].Definition.Replacement {
		if token.Kind != "identifier" {
			continue // Comments disappear; quoted string/character contents stay data.
		}
		for _, namespace := range []string{
			"GO386_", "GOAMD64_", "GOARM_", "GOARM64_", "GOWASM_", "GOEXPERIMENT_",
		} {
			if strings.Contains(token.Text, namespace) {
				return false
			}
		}
	}
	return true
}
