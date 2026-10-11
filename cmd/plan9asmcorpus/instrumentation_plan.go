package main

import (
	"encoding/json"
	"fmt"
	"go/build"
	"path"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

const discoveryInstrumentationPlanProtocol = "exact_source_instrumentation_denominator_v4"
const discoveryInstrumentationLegacyProtocol = "exact_source_instrumentation_denominator_v1"
const discoveryInstrumentationExcludedStatus = "official_target_excluded"
const discoveryInstrumentationSourceRejectedStatus = "original_source_rejected"

// This is a separate mandatory denominator for current ordinary reports,
// including a canonical empty requirements array. Source bytes and actual
// observations are shared by all scopes of the same original package/mode.
// No requirement, marker, or early target rejection supplies a PASS.
type discoveryInstrumentationPlan struct {
	Protocol              string                                                           `json:"protocol"`
	Requirements          []discoveryInstrumentationRequirement                            `json:"requirements"`
	CPPRequirements       []discoveryInstrumentationRequirement                            `json:"cpp_feature_requirements"`
	Sources               map[string]*gotoolprofile.InstrumentationOriginalSourceInventory `json:"package_sources,omitempty"`
	Observations          map[string]*gotoolprofile.InstrumentationExportObservation       `json:"actual_mode_observations,omitempty"`
	Outcomes              []discoveryInstrumentationOutcome                                `json:"outcomes,omitempty"`
	CPPInputs             *discoveryCPPInputs                                              `json:"cpp_inputs,omitempty"`
	ModuleMetadata        string                                                           `json:"original_module_metadata,omitempty"`
	HeaderPlanning        *discoveryInstrumentationHeaderPlanning                          `json:"native_header_planning,omitempty"`
	headerPlanningCapture func(discoveryInstrumentationRequirement, string) (*gotoolprofile.GeneratedHeaderProof, error)
}

type discoveryInstrumentationOutcome struct {
	RequirementID   string                                            `json:"requirement_id"`
	ObservationID   string                                            `json:"observation_id,omitempty"`
	Early           *gotoolprofile.InstrumentationEarlyObservation    `json:"early_rejection,omitempty"`
	TargetExclusion *gotoolprofile.InstrumentationTargetExclusion     `json:"official_target_exclusion,omitempty"`
	SourceRejection *gotoolprofile.InstrumentationSourceRejection     `json:"original_source_rejection,omitempty"`
	PackagePlan     *gotoolprofile.InstrumentationOriginalPackagePlan `json:"original_package_plan,omitempty"`
	TypeSources     *gotoolprofile.InstrumentationTypeSourceProof     `json:"original_type_sources,omitempty"`
	Query           *gotoolprofile.InstrumentationInvocationProof     `json:"metadata_query,omitempty"`
	Objects         *gotoolprofile.InstrumentationInvocationProof     `json:"llvm_objects,omitempty"`
	Status          string                                            `json:"status"`
	Stage           string                                            `json:"stage"`
	Error           string                                            `json:"error,omitempty"`
}

type discoveryInstrumentationRequirement struct {
	ID         string                            `json:"id"`
	BaselineID string                            `json:"baseline_profile_id"`
	Target     string                            `json:"target"`
	Mode       gotoolprofile.InstrumentationMode `json:"mode"`
	CGO        string                            `json:"cgo_enabled"`
	Directory  string                            `json:"package_directory"`
	Tags       []string                          `json:"custom_tags,omitempty"`
	Overrides  map[string]string                 `json:"cpu_experiment_overrides,omitempty"`
	Expected   map[string]bool                   `json:"expected_experiments,omitempty"`
	Pairs      [][2]string                       `json:"source_pairs"`
}

type discoveryInstrumentationSelectionModel struct {
	Mode           gotoolprofile.InstrumentationMode
	CGO            bool
	planningHeader func(discoveryFeatureProfileRequest, string) (*gotoolprofile.GeneratedHeaderProof, error)
}

func captureDiscoveryInstrumentationDenominator(plan *discoveryOrdinarySelectionPlan, files []string, baselines []*discoveryTargetFeatures) error {
	requirements, err := planDiscoveryInstrumentationRequirements(plan, files, baselines)
	if err != nil {
		return err
	}
	if plan.InstrumentationPlan != nil {
		if plan.InstrumentationPlan.Protocol != discoveryInstrumentationPlanProtocol || !reflect.DeepEqual(plan.InstrumentationPlan.Requirements, requirements) {
			return fmt.Errorf("mode denominator changed during ordinary profile registration")
		}
		return nil
	}
	plan.InstrumentationPlan = &discoveryInstrumentationPlan{Protocol: discoveryInstrumentationPlanProtocol, Requirements: requirements}
	return nil
}

func validateDiscoveryInstrumentationDenominator(plan *discoveryOrdinarySelectionPlan, files []string, baselines []*discoveryTargetFeatures) error {
	if plan == nil || plan.InstrumentationPlan == nil ||
		plan.InstrumentationPlan.Protocol != discoveryInstrumentationPlanProtocol && plan.InstrumentationPlan.Protocol != discoveryInstrumentationLegacyProtocol ||
		plan.InstrumentationPlan.Requirements == nil {
		return fmt.Errorf("current ordinary source lacks its complete instrumentation denominator (including the empty set)")
	}
	wanted, err := planDiscoveryInstrumentationRequirements(plan, files, baselines)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(wanted, plan.InstrumentationPlan.Requirements) {
		return fmt.Errorf("mode denominator differs from independent original source-pair replay")
	}
	return nil
}

func discoveryInstrumentationAssemblyRequired(plan *discoveryOrdinarySelectionPlan, file, target string) bool {
	if plan.InstrumentationPlan == nil {
		return false
	}
	for _, requirement := range discoveryInstrumentationAllRequirements(plan.InstrumentationPlan) {
		if requirement.Target == target {
			for _, pair := range requirement.Pairs {
				if pair[0] == file {
					return true
				}
			}
		}
	}
	return false
}

func planDiscoveryInstrumentationRequirements(plan *discoveryOrdinarySelectionPlan, files []string, baselines []*discoveryTargetFeatures) ([]discoveryInstrumentationRequirement, error) {
	if plan == nil || len(baselines) != len(plan.Targets) {
		return nil, fmt.Errorf("mode planning requires every actual target baseline")
	}
	index, err := newDiscoveryInstrumentationSourceIndex(plan, files)
	if err != nil {
		return nil, err
	}
	return planDiscoveryInstrumentationRequirementsIndexed(plan, files, baselines, index)
}

func planDiscoveryInstrumentationRequirementsIndexed(plan *discoveryOrdinarySelectionPlan, files []string, baselines []*discoveryTargetFeatures, index *discoveryInstrumentationSourceIndex) ([]discoveryInstrumentationRequirement, error) {
	byKey := make(map[string]*discoveryInstrumentationRequirement)
	seenTargets := make(map[string]bool)
	for _, baseline := range baselines {
		if baseline == nil || baseline.GoVersion != plan.GoVersion || seenTargets[baseline.Target] || !containsTargetFeature(plan.Targets, baseline.Target) {
			return nil, fmt.Errorf("mode planning has a missing, duplicate or foreign baseline")
		}
		seenTargets[baseline.Target] = true
		ctx, err := discoveryContextForFeatureProfile(baseline)
		if err != nil {
			return nil, err
		}
		ctx.OpenFile = index.open
		for _, asmFile := range files {
			if _, found := index.contents[asmFile]; !found {
				return nil, fmt.Errorf("missing original mode assembly source")
			}
			dir := path.Dir(asmFile)
			if !index.directoryEligible(plan.Module, dir) {
				continue
			}
			for _, goFile := range index.goPartners(dir) {
				mentioned, cgoMentioned, err := index.pairTags(asmFile, goFile)
				if err != nil {
					return nil, err
				}
				for _, mode := range []gotoolprofile.InstrumentationMode{gotoolprofile.InstrumentationRace, gotoolprofile.InstrumentationMSan, gotoolprofile.InstrumentationASan} {
					if !mentioned[string(mode)] {
						continue
					}
					cgovalues := []bool{true}
					if cgoMentioned {
						cgovalues = append(cgovalues, false)
					}
					for _, cgo := range cgovalues {
						request, found, err := planDiscoveryFeaturePairWithExpressions(ctx, baseline, asmFile, goFile, &discoveryInstrumentationSelectionModel{Mode: mode, CGO: cgo}, index.expression)
						if err != nil {
							return nil, fmt.Errorf("mode source pair %s + %s on %s/%s: %w", asmFile, goFile, baseline.Target, mode, err)
						}
						if !found {
							continue
						}
						required, err := discoveryInstrumentationPairRequired(ctx, baseline, request, asmFile, goFile, cgo)
						if err != nil {
							return nil, err
						}
						if !required {
							continue
						}
						r := discoveryInstrumentationRequirement{
							BaselineID: discoveryFeatureProfileID(baseline), Target: baseline.Target, Mode: mode,
							CGO: "1", Directory: dir, Tags: request.customTags, Overrides: request.Overrides, Expected: request.Expected,
						}
						if !cgo {
							r.CGO = "0"
						}
						if len(r.Overrides) == 0 {
							r.Overrides = nil
						}
						keyData, err := json.Marshal(r)
						if err != nil {
							return nil, err
						}
						key := string(keyData)
						if byKey[key] == nil {
							copy := r
							byKey[key] = &copy
						}
						byKey[key].Pairs = append(byKey[key].Pairs, [2]string{asmFile, goFile})
						if len(byKey) > 256 {
							return nil, fmt.Errorf("source-required instrumentation scopes exceed the explicit 256-scope bound")
						}
					}
				}
			}
		}
	}
	result := make([]discoveryInstrumentationRequirement, 0, len(byKey))
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		r := *byKey[key]
		data, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		r.ID = discoveryFeatureBytesSHA256(data)
		result = append(result, r)
	}
	return result, nil
}

func discoveryInstrumentationPairRequired(ctx build.Context, baseline *discoveryTargetFeatures, request discoveryFeatureProfileRequest, asm, goFile string, cgo bool) (bool, error) {
	ctx.CgoEnabled = cgo
	ctx.BuildTags = request.customTags
	minor, _ := discoveryGoMinor(baseline.GoVersion)
	cpuKey := map[string]string{"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM"}[ctx.GOARCH]
	cpu := baseline.Environment[cpuKey]
	if value, changed := request.Overrides[cpuKey]; changed {
		cpu = value
	}
	ctx.ToolTags = discoveryModeledCPUFeatures(ctx.ToolTags, ctx.GOARCH, cpu, minor)
	for tag, value := range request.Expected {
		var kept []string
		for _, old := range ctx.ToolTags {
			if old != tag {
				kept = append(kept, old)
			}
		}
		if value {
			kept = append(kept, tag)
		}
		ctx.ToolTags = kept
	}
	for _, file := range []string{asm, goFile} {
		selected, err := ctx.MatchFile(filepath.FromSlash(path.Dir(file)), path.Base(file))
		if err != nil {
			return false, err
		}
		if !selected {
			return true, nil
		}
	}
	return false, nil
}
