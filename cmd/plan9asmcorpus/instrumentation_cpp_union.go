package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// Original Go/ASM constraints define the base denominator. The separately
// registered complete mode CPP graph defines additional CPU requests. Neither
// a proposal nor an ordinary profile supplies an actual mode object.
func discoveryInstrumentationAllRequirements(proof *discoveryInstrumentationPlan) []discoveryInstrumentationRequirement {
	result := append([]discoveryInstrumentationRequirement(nil), proof.Requirements...)
	return append(result, proof.CPPRequirements...)
}

func instrumentationRequirementKey(requirement discoveryInstrumentationRequirement) (string, error) {
	requirement.ID, requirement.Pairs = "", nil
	if len(requirement.Overrides) == 0 {
		requirement.Overrides = nil
	}
	encoded, err := json.Marshal(requirement)
	return string(encoded), err
}

func planDiscoveryInstrumentationCPPRequirements(plan *discoveryOrdinarySelectionPlan, baselines []*discoveryTargetFeatures, files []string, contexts ...context.Context) ([]discoveryInstrumentationRequirement, error) {
	if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
		return nil, err
	}
	proof := plan.InstrumentationPlan
	if proof == nil || proof.CPPInputs == nil {
		return nil, fmt.Errorf("mode CPU planning lacks its original CPP registration")
	}
	index, err := newDiscoveryInstrumentationSourceIndex(plan, files)
	if err != nil {
		return nil, err
	}
	byTarget := make(map[string]*discoveryTargetFeatures)
	for _, baseline := range baselines {
		if baseline == nil || byTarget[baseline.Target] != nil {
			return nil, fmt.Errorf("mode CPU planning has a missing or repeated baseline")
		}
		byTarget[baseline.Target] = baseline
	}
	baseKeys := make(map[string]bool)
	for _, requirement := range proof.Requirements {
		key, err := instrumentationRequirementKey(requirement)
		if err != nil {
			return nil, err
		}
		baseKeys[key] = true
	}
	cppPlan := *plan
	cppPlan.CPPInputs = proof.CPPInputs
	if proof.HeaderPlanning != nil {
		proof.HeaderPlanning.used = make(map[string]bool)
	}
	byKey := make(map[string]*discoveryInstrumentationRequirement)
	for _, requirement := range proof.Requirements {
		baseline := byTarget[requirement.Target]
		if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
			return nil, err
		}
		if baseline == nil || requirement.BaselineID != discoveryFeatureProfileID(baseline) {
			return nil, fmt.Errorf("mode CPU request changed its independently observed baseline")
		}
		ctx, err := discoveryContextForFeatureProfile(baseline)
		if err != nil {
			return nil, err
		}
		ctx.OpenFile = index.open
		model := &discoveryInstrumentationSelectionModel{
			Mode: requirement.Mode, CGO: requirement.CGO == "1",
		}
		if proof.HeaderPlanning != nil || proof.headerPlanningCapture != nil {
			model.planningHeader = func(request discoveryFeatureProfileRequest, assembly string) (*gotoolprofile.GeneratedHeaderProof, error) {
				query := requirement
				query.ID, query.Pairs = "", nil
				query.Overrides, query.Expected, query.Tags = request.Overrides, request.Expected, request.customTags
				return discoveryInstrumentationPlanningHeader(plan, query, assembly, baselines)
			}
		}
		initial := discoveryFeatureProfileRequest{
			Target: requirement.Target, Baseline: len(requirement.Overrides) == 0,
			Overrides: cloneDiscoveryCPPEnvironment(requirement.Overrides),
			Expected:  requirement.Expected, customTags: requirement.Tags,
		}
		for _, pair := range requirement.Pairs {
			if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
				return nil, err
			}
			// An officially excluded target has no selected CPP roots. Such a
			// requirement still keeps its independent early-rule witness.
			if !instrumentationCPPUnitPresent(proof.CPPInputs, pair[0]) {
				continue
			}
			requests, err := planDiscoveryCPPFeaturePairWithMode(&cppPlan, ctx, baseline, pair[0], pair[1], initial, model, contexts...)
			if err != nil {
				return nil, fmt.Errorf("mode CPU pair %s + %s: %w", pair[0], pair[1], err)
			}
			for _, request := range requests {
				candidate := discoveryInstrumentationRequirement{
					BaselineID: requirement.BaselineID, Target: requirement.Target, Mode: requirement.Mode,
					CGO: requirement.CGO, Directory: requirement.Directory, Tags: request.customTags,
					Overrides: request.Overrides, Expected: request.Expected,
				}
				key, err := instrumentationRequirementKey(candidate)
				if err != nil {
					return nil, err
				}
				if baseKeys[key] {
					continue
				}
				if byKey[key] == nil {
					byKey[key] = &candidate
				}
				found := false
				for _, old := range byKey[key].Pairs {
					found = found || old == pair
				}
				if !found {
					byKey[key].Pairs = append(byKey[key].Pairs, pair)
				}
				if len(byKey)+len(proof.Requirements) > 256 {
					return nil, fmt.Errorf("complete source/CPP mode union exceeds the explicit 256-scope bound")
				}
			}
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]discoveryInstrumentationRequirement, 0, len(keys))
	for _, key := range keys {
		requirement := *byKey[key]
		sort.Slice(requirement.Pairs, func(i, j int) bool {
			if requirement.Pairs[i][0] != requirement.Pairs[j][0] {
				return requirement.Pairs[i][0] < requirement.Pairs[j][0]
			}
			return requirement.Pairs[i][1] < requirement.Pairs[j][1]
		})
		encoded, err := json.Marshal(requirement)
		if err != nil {
			return nil, err
		}
		requirement.ID = discoveryFeatureBytesSHA256(encoded)
		result = append(result, requirement)
	}
	if err := validateDiscoveryInstrumentationHeaderPlanningConsumption(proof.HeaderPlanning); err != nil {
		return nil, err
	}
	return result, nil
}

func instrumentationCPPUnitPresent(inputs *discoveryCPPInputs, file string) bool {
	for _, unit := range inputs.Units {
		if unit.File == file {
			return true
		}
	}
	return false
}

func validateDiscoveryInstrumentationCPPUnion(plan *discoveryOrdinarySelectionPlan, baselines []*discoveryTargetFeatures, files []string) error {
	wanted, err := planDiscoveryInstrumentationCPPRequirements(plan, baselines, files)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(wanted, plan.InstrumentationPlan.CPPRequirements) {
		return fmt.Errorf("mode CPU union differs from its independent original source/CPP replay")
	}
	return nil
}

func discoveryInstrumentationBaselines(profiles []discoveryFeatureProfile) []*discoveryTargetFeatures {
	var result []*discoveryTargetFeatures
	for _, profile := range profiles {
		if profile.Request.Baseline {
			result = append(result, profile.Observed)
		}
	}
	return result
}
