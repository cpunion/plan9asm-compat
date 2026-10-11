package main

import (
	"context"
	"fmt"
	"go/build"
	"io"
	"path"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// CPP has a separate feature namespace: for example GOAMD64_v3 is exclusive,
// whereas the amd64.v3 build tag is also true at v4. Enumerate the finite CPU
// environments and replay local macro definedness before proposing profiles.
// Only reachable branch sides require profiles; inactive outer conditions do
// not create a claim of branch execution or full instruction-form coverage.
func planDiscoveryCPPFeaturePair(plan *discoveryOrdinarySelectionPlan, ctx build.Context, baseline *discoveryTargetFeatures, asmFile, goFile string, initial discoveryFeatureProfileRequest, contexts ...context.Context) ([]discoveryFeatureProfileRequest, error) {
	return planDiscoveryCPPFeaturePairWithMode(plan, ctx, baseline, asmFile, goFile, initial, nil, contexts...)
}

func planDiscoveryCPPFeaturePairWithMode(plan *discoveryOrdinarySelectionPlan, ctx build.Context, baseline *discoveryTargetFeatures, asmFile, goFile string, initial discoveryFeatureProfileRequest, mode *discoveryInstrumentationSelectionModel, contexts ...context.Context) ([]discoveryFeatureProfileRequest, error) {
	return planDiscoveryCPPFeaturePairWithIndex(plan, ctx, baseline, asmFile, goFile, initial,
		mode, &discoveryCPPPlanningSourceIndex{}, contexts...)
}

func planDiscoveryCPPFeaturePairWithIndex(plan *discoveryOrdinarySelectionPlan, ctx build.Context, baseline *discoveryTargetFeatures,
	asmFile, goFile string, initial discoveryFeatureProfileRequest, mode *discoveryInstrumentationSelectionModel,
	sourceIndex *discoveryCPPPlanningSourceIndex, contexts ...context.Context) ([]discoveryFeatureProfileRequest, error) {
	if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
		return nil, err
	}
	if len(contexts) == 1 && ctx.OpenFile != nil {
		open := ctx.OpenFile
		ctx.OpenFile = func(name string) (io.ReadCloser, error) {
			if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
				return nil, err
			}
			return open(name)
		}
	}
	if plan.DocumentationSourceProtocol == discoveryDocumentationProtocol && possibleDocumentationDirectory(plan, path.Dir(asmFile)) {
		sources, directories, err := ordinarySelectionBytes(plan)
		if err != nil {
			return nil, err
		}
		if alwaysDocumentationDirectory(path.Dir(asmFile), sources, directories[path.Dir(asmFile)]) {
			// No CPP proposal from a directory that cannot have a Go package.
			// The final source exclusion still requires actual typed queries.
			return nil, nil
		}
	}
	for _, rejection := range plan.PreCPPRejections {
		if rejection.File == asmFile {
			// An unknown first control is unconditional and rejects before
			// any CPP feature branch. All final selected scopes still need
			// their own actual assembler and package-role proof.
			return nil, nil
		}
	}
	if plan.CPPInputs == nil {
		return nil, nil
	}
	var unit *discoveryCPPUnit
	for index := range plan.CPPInputs.Units {
		if plan.CPPInputs.Units[index].File == asmFile {
			unit = &plan.CPPInputs.Units[index]
			break
		}
	}
	if unit == nil {
		return nil, fmt.Errorf("source-required ASM pair lacks its exact CPP unit: %s", asmFile)
	}
	registration := plan.CPPInputs
	if sourceIndex != nil && registration.Protocol == discoveryReplayCPPInputsProtocol {
		var err error
		registration, err = indexDiscoveryReplayCPPSources(registration, sourceIndex)
		if err != nil {
			return nil, err
		}
	}
	directives, err := discoveryCPPUnitDirectives(registration, *unit, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	fullReplay := plan.CPPInputs.Protocol == discoveryReplayCPPInputsProtocol
	if !fullReplay && !discoveryCPPHasFeatureConditions(directives) {
		return nil, nil
	}
	for _, directive := range directives {
		if (directive.Kind == "ifdef" || directive.Kind == "ifndef") && strings.HasPrefix(directive.Name, "GOEXPERIMENT_") {
			return nil, fmt.Errorf("CPP experiment macro requires actual package-role binding, not an ordinary/custom feature assumption")
		}
	}
	minor, err := discoveryGoMinor(baseline.GoVersion)
	if err != nil {
		return nil, err
	}
	cpuKey := discoveryCPPFeatureCPUKey(ctx.GOARCH)
	values := discoveryCPPFeatureCPUValues(ctx.GOARCH, minor, baseline.Environment[cpuKey])
	if err := validateDiscoveryCPPFeatureNamespace(directives, ctx.GOARCH); err != nil {
		return nil, err
	}
	// A generated definition is not fixed-false before actual package loading.
	// A CPU branch nested below such a predicate can become reachable in a
	// different selected Go layout. Observe every legal CPU proposal in this
	// bounded case; the actual per-profile header still decides consumption.
	// Historical directive replay cannot observe whether a registered header
	// is opened. Full-source replay can: a raw String candidate is not an
	// active generated input when every concrete replay succeeds without it.
	deferredPresence := !fullReplay && discoveryCPPDeferredPresenceMayAffectCPU(*unit, directives)
	covered := make(map[string]bool)
	var observedHeader *gotoolprofile.GeneratedHeaderProof
	cover := func(request discoveryFeatureProfileRequest) (bool, error) {
		if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
			return false, err
		}
		env := cloneDiscoveryCPPEnvironment(baseline.Environment)
		for key, value := range request.Overrides {
			env[key] = value
		}
		defines, err := plan9asm.GoAssemblerDefinesForEnvironment(ctx.GOOS, ctx.GOARCH, env)
		if err != nil {
			return false, err
		}
		var keys map[string]bool
		if fullReplay {
			observation, _, err := replayDiscoveryOriginalCPPWithIndex(plan.CPPInputs, *unit, nil, defines, sourceIndex)
			if err != nil {
				// No fabricated native header is a planning input. Every legal
				// CPU proposal is retained when actual header presence is needed;
				// its actual package/header/consumer must still close later.
				if gotoolprofile.CPPOriginalNeedsGeneratedHeader(err, unit.File) {
					if mode != nil && mode.planningHeader == nil || mode == nil && plan.HeaderPlanning == nil && plan.headerPlanningCapture == nil {
						deferredPresence = true
						return false, nil
					}
					var header *gotoolprofile.GeneratedHeaderProof
					var queryErr error
					if mode != nil {
						header, queryErr = mode.planningHeader(request, unit.File)
					} else {
						header, queryErr = discoveryPlanningHeader(plan, request, unit.File, request.customTags)
					}
					if queryErr != nil {
						if _, unsupported := queryErr.(*discoveryHeaderPlanningUnsupported); unsupported {
							deferredPresence = true
							return false, nil
						}
						return false, queryErr
					}
					observedHeader = header
					observation, _, err = replayDiscoveryOriginalCPPWithIndex(plan.CPPInputs, *unit, header, defines, sourceIndex)
				}
				if err != nil {
					return false, fmt.Errorf("full original CPP planning replay: %w", err)
				}
			}
			keys, err = discoveryCPPBranchCoverage(observation)
			if err != nil {
				return false, err
			}
			if mode != nil {
				// Imported CPU-selected constants can change operands without
				// changing any branch side. Only identical full same-mode CPP
				// output may share this planning scope; a digest proves no object.
				keys[discoveryCPPExpandedOutputCoverageKey(unit.File, observation.Output)] = true
			}
		} else {
			states, err := replayDiscoveryCPPConditions(directives, defines)
			if err != nil {
				return false, fmt.Errorf("bounded CPP replay requires concrete source diagnosis: %w", err)
			}
			keys = make(map[string]bool)
			for index, state := range states {
				if state.OuterActive {
					keys[fmt.Sprintf("%d/%t", index, state.Then)] = true
				}
			}
		}
		added := false
		for key := range keys {
			if !covered[key] {
				covered[key], added = true, true
			}
		}
		return added, nil
	}
	if _, err := cover(initial); err != nil {
		return nil, err
	}
	conditionFree := false
	if mode == nil && fullReplay && !deferredPresence && len(covered) == 0 {
		conditionFree, err = discoveryCPPConditionFreeWithIndex(plan, *unit, observedHeader, sourceIndex, contexts...)
		if err != nil {
			return nil, err
		}
	}
	var requests []discoveryFeatureProfileRequest
	for _, value := range values {
		if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
			return nil, err
		}
		if err := validateDiscoveryCPUEnvironment(ctx.GOARCH, value, minor); err != nil {
			continue
		}
		// This is only a planning model. captureDiscoveryFeatureProfiles will
		// observe the proposal with the actual Go driver before accepting it.
		model := *baseline
		model.Environment = cloneDiscoveryCPPEnvironment(baseline.Environment)
		model.Environment[cpuKey] = value
		model.ToolTags = discoveryModeledCPUFeatures(baseline.ToolTags, ctx.GOARCH, value, minor)
		modeledContext := ctx
		modeledContext.ToolTags = model.ToolTags
		request, found, err := planDiscoveryFeaturePairWithMode(modeledContext, &model, asmFile, goFile, mode)
		if err != nil {
			return nil, err
		}
		if conditionFree {
			// MatchFile above still models every original Go pair/CPU proposal.
			// Recheck the full graph after caller-controlled OpenFile callbacks,
			// even for a nonmatching pair. An earlier empty set is not a proof.
			conditionFree, err = discoveryCPPConditionFreeWithIndex(plan, *unit, observedHeader, sourceIndex, contexts...)
			if err != nil {
				return nil, err
			}
		}
		if !found {
			continue
		}
		requestedCPU := value
		if override, present := request.Overrides[cpuKey]; present {
			requestedCPU = override
		}
		if requestedCPU == baseline.Environment[cpuKey] {
			delete(request.Overrides, cpuKey)
		} else {
			request.Overrides[cpuKey] = requestedCPU
		}
		request.Baseline = len(request.Overrides) == 0
		request.pairs = [][2]string{{asmFile, goFile}}
		if conditionFree {
			continue
		}
		added, err := cover(request)
		if err != nil {
			return nil, err
		}
		if added || deferredPresence {
			requests = append(requests, request)
		}
	}
	return requests, nil
}

func discoveryCPPExpandedOutputCoverageKey(file, output string) string {
	return "expanded/" + file + "\x00" + discoveryFeatureBytesSHA256([]byte(output))
}

func discoveryCPPDeferredPresenceMayAffectCPU(unit discoveryCPPUnit, directives []discoveryCPPDirective) bool {
	generated := false
	for _, kind := range unit.DeferredIncludes {
		generated = generated || kind == "generated_go_asm"
	}
	if !generated {
		return false
	}
	for _, directive := range directives {
		if directive.Kind != "ifdef" && directive.Kind != "ifndef" {
			continue
		}
		cpuName := false
		for _, prefix := range []string{"GO386_", "GOAMD64_", "GOARM_", "GOARM64_", "GOWASM_"} {
			cpuName = cpuName || strings.HasPrefix(directive.Name, prefix)
		}
		if !cpuName {
			return true
		}
	}
	return false
}

func discoveryCPPFeatureCPUKey(arch string) string {
	return map[string]string{"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM"}[arch]
}

func discoveryCPPFeatureCPUValues(arch string, minor int, baseline string) []string {
	values := []string{baseline}
	switch arch {
	case "386":
		values = append(values, "sse2", "softfloat")
	case "amd64":
		values = append(values, "v1", "v2", "v3", "v4")
	case "arm":
		values = append(values, "5", "6", "7")
	case "arm64":
		if minor >= 23 {
			// Keep high-level Go constraints. Actual Go registers ,lse but
			// no ,nolse; every level above v8.0 already implies LSE. A high-
			// level Go declaration has no reachable non-LSE CPP variant.
			for _, tag := range discoveryCPUFeatureCandidates() {
				if strings.HasPrefix(tag, "arm64.") {
					level := strings.TrimPrefix(tag, "arm64.")
					values = append(values, level, level+",lse")
				}
			}
		}
	case "wasm":
		values = append(values, "", "satconv", "signext", "satconv,signext")
	}
	return uniqueDiscoveryStrings(values)
}

func cloneDiscoveryCPPEnvironment(environment map[string]string) map[string]string {
	copy := make(map[string]string, len(environment))
	for key, value := range environment {
		copy[key] = value
	}
	return copy
}

func discoveryCPPHasFeatureConditions(directives []discoveryCPPDirective) bool {
	for _, directive := range directives {
		if directive.Kind != "ifdef" && directive.Kind != "ifndef" {
			continue
		}
		for _, prefix := range []string{"GO386_", "GOAMD64_", "GOARM_", "GOARM64_", "GOWASM_", "GOEXPERIMENT_"} {
			if strings.HasPrefix(directive.Name, prefix) {
				return true
			}
		}
	}
	return false
}

func validateDiscoveryCPPFeatureNamespace(directives []discoveryCPPDirective, arch string) error {
	key := discoveryCPPFeatureCPUKey(arch)
	known := map[string][]string{
		"386":   {"GO386_sse2", "GO386_softfloat"},
		"amd64": {"GOAMD64_v1", "GOAMD64_v2", "GOAMD64_v3", "GOAMD64_v4"},
		"arm":   {"GOARM_5", "GOARM_6", "GOARM_7"},
		"arm64": {"GOARM64_LSE"},
		// Go's audited asmArgs does not register these WASM macros. Keep
		// their known source spelling fixed-false, not fake -D or -tags.
		"wasm": {"GOWASM_satconv", "GOWASM_signext"},
	}
	for _, directive := range directives {
		if (directive.Kind == "ifdef" || directive.Kind == "ifndef") && strings.HasPrefix(directive.Name, key+"_") &&
			!containsTargetFeature(known[arch], directive.Name) {
			return fmt.Errorf("unknown target CPU CPP namespace %s (not baseline N/A)", directive.Name)
		}
	}
	return nil
}
