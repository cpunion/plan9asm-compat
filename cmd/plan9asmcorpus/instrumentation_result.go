package main

import (
	"fmt"
	"path"
	"reflect"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func validateDiscoveryInstrumentationObservation(requirement discoveryInstrumentationRequirement, profiles []discoveryFeatureProfile, observed *gotoolprofile.InstrumentationExportObservation) error {
	if err := gotoolprofile.ValidateInstrumentationExportObservation(observed); err != nil {
		return err
	}
	return validateDiscoveryInstrumentationEarlyBinding(requirement, profiles, observed.Early)
}

func validateDiscoveryInstrumentationEarlyBinding(requirement discoveryInstrumentationRequirement, profiles []discoveryFeatureProfile, early *gotoolprofile.InstrumentationEarlyObservation) error {
	if early.Target != requirement.Target || early.Mode != requirement.Mode || early.CGOEnabled != requirement.CGO {
		return fmt.Errorf("actual mode observation changed its independently required target/mode/CGO")
	}
	var baseline *discoveryTargetFeatures
	for _, profile := range profiles {
		if profile.ID == requirement.BaselineID && profile.Request.Baseline {
			baseline = profile.Observed
		}
	}
	if baseline == nil || baseline.Target != early.Target || baseline.GoVersion != early.SourceRules.GoVersion ||
		baseline.DriverSHA256 != early.BaselineFeatures.DriverSHA256 ||
		!reflect.DeepEqual(baseline.ToolSourceSHA256, early.BaselineFeatures.ToolSourceSHA256) {
		return fmt.Errorf("mode observation lacks its independently observed source/driver/CPU baseline")
	}
	for key, value := range baseline.Environment {
		if key == "CGO_ENABLED" || key == "GOVERSION" {
			continue
		}
		if override, changed := requirement.Overrides[key]; changed {
			value = override
		}
		if early.Environment[key] != value {
			return fmt.Errorf("actual mode environment differs from its original CPU/experiment request: %s", key)
		}
	}
	for tag, expected := range requirement.Expected {
		if value, found := early.BaselineFeatures.MarkerSelection[tag]; !found || value != expected {
			return fmt.Errorf("actual mode foundation contradicted its required experiment")
		}
	}
	return nil
}

// The portable reader rebuilds the private ConsumerInput from its existing
// exact ZIP-bound source plan and actual mode observation. The absolute
// offline root is never opened, published, or used for an actual invocation;
// private physical roots are deliberately absent from the shared input SHA.
func validateDiscoveryInstrumentationResult(result discoveryCorpusResult, profiles []discoveryFeatureProfile, scope []string) (int, []string, error) {
	plan := result.OrdinarySelectionPlan
	if plan == nil || plan.Module != result.Module || plan.Version != result.Version {
		return 0, nil, fmt.Errorf("mode denominator changed its exact original module/version")
	}
	var baselines []*discoveryTargetFeatures
	for _, profile := range profiles {
		if profile.Request.Baseline {
			baselines = append(baselines, profile.Observed)
		}
	}
	if err := validateDiscoveryInstrumentationDenominator(plan, scope, baselines); err != nil {
		return 0, nil, err
	}
	proof := plan.InstrumentationPlan
	if _, err := discoveryInstrumentationModulePath(plan); err != nil {
		return 0, nil, err
	}
	if len(proof.Requirements) == 0 {
		if len(proof.Outcomes) != 0 || len(proof.Sources) != 0 || len(proof.Observations) != 0 || proof.CPPInputs != nil || proof.ModuleMetadata != "" || proof.CPPRequirements != nil || proof.HeaderPlanning != nil || result.InstrumentationTranslations != 0 || result.InstrumentationTargetExclusions != 0 {
			return 0, nil, fmt.Errorf("empty instrumentation denominator carries unexplained mode evidence/counts")
		}
		return 0, nil, nil
	}
	allowNonpass := result.Status == discoveryStatusFailed
	requirements := discoveryInstrumentationAllRequirements(proof)
	if len(proof.Outcomes) != len(requirements) || !allowNonpass && proof.CPPInputs == nil {
		return 0, nil, fmt.Errorf("source-required mode scopes lost their separate outcomes/CPP graph")
	}
	seenObservations, seenPackages, selected := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	objects, exclusions, sourceRejections := 0, 0, 0
	for index, requirement := range requirements {
		outcome := proof.Outcomes[index]
		if outcome.RequirementID != requirement.ID {
			return 0, nil, fmt.Errorf("mode outcome differs from its independent source requirement")
		}
		if outcome.Status == discoveryInstrumentationExcludedStatus {
			if err := validateDiscoveryInstrumentationTargetExclusion(plan, requirement, outcome, profiles); err != nil {
				return 0, nil, err
			}
			exclusions++
			seenPackages[requirement.Directory] = true
			continue
		}
		if outcome.TargetExclusion != nil {
			return 0, nil, fmt.Errorf("nonexcluded mode carries official target-exclusion evidence")
		}
		if outcome.Status == discoveryInstrumentationSourceRejectedStatus {
			packagePlan, err := validateDiscoveryInstrumentationSourceRejection(plan, requirement, outcome, profiles)
			if err != nil {
				return 0, nil, err
			}
			seenObservations[outcome.ObservationID], seenPackages[requirement.Directory] = true, true
			sourceRejections++
			for _, file := range packagePlan.SFiles {
				if !containsTargetFeature(scope, file) || path.Dir(file) != requirement.Directory {
					return 0, nil, fmt.Errorf("rejected mode claims a foreign or undiscovered assembly source")
				}
				selected[file] = true // Original CPP registration, never an executed object.
			}
			continue
		}
		if outcome.SourceRejection != nil {
			return 0, nil, fmt.Errorf("nonrejected mode carries original source-exclusion evidence")
		}
		if allowNonpass && outcome.Status != "llvm_objects_only" {
			if err := validateDiscoveryInstrumentationNonpass(plan, requirement, outcome, profiles, seenObservations, seenPackages, selected); err != nil {
				return 0, nil, err
			}
			continue
		}
		if outcome.Status != "llvm_objects_only" || outcome.Stage != "complete" || outcome.Error != "" || outcome.Early != nil {
			return 0, nil, fmt.Errorf("instrumentation prerequisite/source/export/consumer failure cannot satisfy a candidate")
		}
		observed := proof.Observations[outcome.ObservationID]
		if observed == nil || outcome.ObservationID != gotoolprofile.InstrumentationEarlyProfileID(observed.Early) {
			return 0, nil, fmt.Errorf("mode outcome has a missing or substituted actual observation")
		}
		if err := validateDiscoveryInstrumentationObservation(requirement, profiles, observed); err != nil {
			return 0, nil, err
		}
		seenObservations[outcome.ObservationID], seenPackages[requirement.Directory] = true, true
		inventory := proof.Sources[requirement.Directory]
		input := discoveryInstrumentationOriginalInput(plan, observed, "/original-offline-source", nil)
		packagePlan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observed.Early, requirement.Directory, requirement.Tags)
		if err != nil {
			return 0, nil, err
		}
		input.AsmFiles = append([]string(nil), packagePlan.SFiles...)
		packagePlan, err = gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observed.Early, requirement.Directory, requirement.Tags)
		if err != nil || !reflect.DeepEqual(packagePlan, outcome.PackagePlan) {
			return 0, nil, fmt.Errorf("mode outcome changed the complete original package selection: %v", err)
		}
		wrapped, err := gotoolprofile.NewInstrumentationConsumerInput(input, inventory, observed, packagePlan)
		if err != nil {
			return 0, nil, err
		}
		wrapped.TypeSources = outcome.TypeSources
		if err := gotoolprofile.ValidateInstrumentationInvocation(wrapped, gotoolprofile.InstrumentationMetadataQuery, nil, nil, outcome.Query); err != nil {
			return 0, nil, err
		}
		if outcome.Objects == nil || outcome.Objects.LLVM == nil {
			return 0, nil, fmt.Errorf("mode scope lacks actual LLVM objects; a query is not completion")
		}
		if err := gotoolprofile.ValidateInstrumentationInvocation(wrapped, gotoolprofile.InstrumentationObjectCompile, outcome.Query.Metadata, outcome.Objects.LLVM, outcome.Objects); err != nil {
			return 0, nil, err
		}
		for _, file := range packagePlan.SFiles {
			if !containsTargetFeature(scope, file) || path.Dir(file) != requirement.Directory {
				return 0, nil, fmt.Errorf("mode objects claim non-discovered assembly or a foreign package")
			}
			selected[file] = true
		}
		objects += outcome.Objects.ObjectCount
	}
	if len(seenObservations) != len(proof.Observations) || len(seenPackages) != len(proof.Sources) {
		return 0, nil, fmt.Errorf("mode inventory has unexplained observations or original packages")
	}
	if proof.CPPInputs != nil {
		if proof.CPPInputs.Protocol != plan.CPPSourceProtocol {
			return 0, nil, fmt.Errorf("mode original CPP source protocol was downgraded or substituted")
		}
		if err := validateDiscoveryCPPInputs(proof.CPPInputs, plan, sortedDiscoverySet(selected)); err != nil {
			return 0, nil, err
		}
		if !allowNonpass {
			if len(proof.CPPInputs.Units) != len(selected) {
				return 0, nil, fmt.Errorf("mode raw CPP has an unexplained selected root")
			}
		}
		if proof.CPPRequirements != nil || !allowNonpass || objects != 0 || proof.HeaderPlanning != nil {
			if err := validateDiscoveryInstrumentationCPPUnion(plan, baselines, scope); err != nil {
				return 0, nil, err
			}
		}
	} else if len(selected) != 0 && objects != 0 {
		return 0, nil, fmt.Errorf("consumed mode scope has no original CPP registration")
	} else if proof.CPPRequirements != nil {
		return 0, nil, fmt.Errorf("mode CPU union lost its original CPP registration")
	}
	if result.InstrumentationTranslations != objects {
		return 0, nil, fmt.Errorf("mode object count differs from the independently required consumed scopes")
	}
	if result.InstrumentationTargetExclusions != exclusions {
		return 0, nil, fmt.Errorf("mode target-exclusion count differs from independently replayed scopes")
	}
	if exclusions == len(requirements) && !allowNonpass {
		return 0, nil, fmt.Errorf("all required instrumentation modes are excluded; no scope-only candidate pass is authorized")
	}
	if sourceRejections != 0 && !allowNonpass && (result.Translations == 0 || result.Translations < objects) {
		return 0, nil, fmt.Errorf("source-refused mode cannot authorize a candidate without independently compiled objects")
	}
	// Registered CPP roots include source-refused packages. The public file
	// union counts only physically compiled objects, not those zero-object roots.
	return objects, discoveryInstrumentationExecutedFiles(plan), nil
}

func validateDiscoveryInstrumentationNonpass(plan *discoveryOrdinarySelectionPlan, requirement discoveryInstrumentationRequirement, outcome discoveryInstrumentationOutcome, profiles []discoveryFeatureProfile, observations, packages, selected map[string]bool) error {
	if outcome.SourceRejection != nil || outcome.Error == "" || outcome.Status != "failed" && outcome.Status != "early_target_rejected" {
		return fmt.Errorf("mode nonpass lacks its exact stage/diagnostic or claims an unknown successful status")
	}
	switch outcome.Stage {
	case "environment", "early_rules", "marker_export", "original_sources", "original_selection", "cpp_registration", "original_graph", "metadata_query", "llvm_objects", "physical_readback":
	default:
		return fmt.Errorf("mode nonpass has an unregistered execution stage")
	}
	if outcome.Early != nil {
		if plan.InstrumentationPlan.Protocol != discoveryInstrumentationLegacyProtocol {
			return fmt.Errorf("v2 cannot relabel an untagged v1 early observation as an official scope exclusion")
		}
		if outcome.Status != "early_target_rejected" || outcome.Stage != "early_rules" || outcome.ObservationID != "" || outcome.Query != nil || outcome.Objects != nil || outcome.PackagePlan != nil || outcome.TypeSources != nil {
			return fmt.Errorf("early target rejection was combined with export/LLVM completion")
		}
		if err := gotoolprofile.ValidateInstrumentationEarlyObservation(outcome.Early); err != nil {
			return err
		}
		if err := validateDiscoveryInstrumentationEarlyBinding(requirement, profiles, outcome.Early); err != nil {
			return err
		}
		if outcome.Early.Target != requirement.Target || outcome.Early.Mode != requirement.Mode || outcome.Early.CGOEnabled != requirement.CGO || outcome.Early.Status == gotoolprofile.InstrumentationEarlyRuleAccepted {
			return fmt.Errorf("mode early rejection differs from the exact required source scope")
		}
		return nil
	}
	if outcome.Status == "early_target_rejected" {
		return fmt.Errorf("early target rejection lacks actual registered source/driver evidence")
	}
	if outcome.ObservationID == "" {
		if outcome.PackagePlan != nil || outcome.TypeSources != nil || outcome.Query != nil || outcome.Objects != nil || outcome.Stage != "environment" && outcome.Stage != "early_rules" && outcome.Stage != "marker_export" {
			return fmt.Errorf("mode failure relabeled an unobserved marker as source/export/objects")
		}
		return nil
	}
	proof := plan.InstrumentationPlan
	observed := proof.Observations[outcome.ObservationID]
	if observed == nil || outcome.ObservationID != gotoolprofile.InstrumentationEarlyProfileID(observed.Early) {
		return fmt.Errorf("mode failure has a missing or foreign observation")
	}
	if err := validateDiscoveryInstrumentationObservation(requirement, profiles, observed); err != nil {
		return err
	}
	observations[outcome.ObservationID] = true
	inventory := proof.Sources[requirement.Directory]
	if inventory == nil {
		if outcome.Stage != "original_sources" || outcome.PackagePlan != nil || outcome.TypeSources != nil || outcome.Query != nil || outcome.Objects != nil {
			return fmt.Errorf("mode failure lost required complete original source bytes")
		}
		return nil
	}
	input := discoveryInstrumentationOriginalInput(plan, observed, "/original-offline-source", nil)
	if err := gotoolprofile.ValidateInstrumentationOriginalSourceInventory(input, requirement.Directory, inventory); err != nil {
		return err
	}
	packages[requirement.Directory] = true
	packagePlan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observed.Early, requirement.Directory, requirement.Tags)
	if err != nil {
		if outcome.Stage != "original_selection" || outcome.PackagePlan != nil || outcome.TypeSources != nil || outcome.Query != nil || outcome.Objects != nil {
			return fmt.Errorf("mode source failure was relabeled as export/LLVM completion")
		}
		return nil
	}
	input.AsmFiles = append([]string(nil), packagePlan.SFiles...)
	packagePlan, err = gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observed.Early, requirement.Directory, requirement.Tags)
	if err != nil {
		return err
	}
	for _, file := range packagePlan.SFiles {
		selected[file] = true
	}
	if outcome.PackagePlan != nil && !reflect.DeepEqual(outcome.PackagePlan, packagePlan) {
		return fmt.Errorf("mode failure changed its independent original package layout/selection")
	}
	if (outcome.Stage == "original_graph" || outcome.Stage == "metadata_query" || outcome.Stage == "llvm_objects" || outcome.Stage == "physical_readback") && outcome.PackagePlan == nil {
		return fmt.Errorf("mode failure erased its preceding original package plan")
	}
	if (outcome.Stage == "llvm_objects" || outcome.Stage == "physical_readback") && outcome.Query == nil {
		return fmt.Errorf("mode failure erased its preceding actual metadata query")
	}
	if outcome.Stage == "physical_readback" && outcome.Objects == nil {
		return fmt.Errorf("mode physical readback failure erased its actual object proof")
	}
	if outcome.TypeSources != nil {
		if outcome.PackagePlan == nil || outcome.Stage != "original_graph" && outcome.Stage != "metadata_query" && outcome.Stage != "llvm_objects" && outcome.Stage != "physical_readback" {
			return fmt.Errorf("mode failure carries imported type sources before actual original graph capture")
		}
		wrapped, err := gotoolprofile.NewInstrumentationConsumerInput(input, inventory, observed, packagePlan)
		if err != nil {
			return err
		}
		if err := gotoolprofile.ValidateInstrumentationTypeSources(wrapped, outcome.TypeSources); err != nil {
			return err
		}
	}
	if outcome.Query != nil {
		wrapped, err := gotoolprofile.NewInstrumentationConsumerInput(input, inventory, observed, packagePlan)
		if err != nil {
			return err
		}
		wrapped.TypeSources = outcome.TypeSources
		if err := gotoolprofile.ValidateInstrumentationInvocation(wrapped, gotoolprofile.InstrumentationMetadataQuery, nil, nil, outcome.Query); err != nil {
			return err
		}
		if outcome.Objects != nil {
			return gotoolprofile.ValidateInstrumentationInvocation(wrapped, gotoolprofile.InstrumentationObjectCompile, outcome.Query.Metadata, outcome.Objects.LLVM, outcome.Objects)
		}
	} else if outcome.Objects != nil {
		return fmt.Errorf("failed mode object scope lost its independent metadata query")
	}
	return nil
}

func discoveryInstrumentationExecutedFiles(plan *discoveryOrdinarySelectionPlan) []string {
	selected := make(map[string]bool)
	if plan != nil && plan.InstrumentationPlan != nil {
		for _, outcome := range plan.InstrumentationPlan.Outcomes {
			if outcome.Status == "llvm_objects_only" && outcome.Error == "" && outcome.Objects != nil {
				for _, file := range outcome.Objects.AsmFiles {
					selected[file] = true
				}
			}
		}
	}
	return sortedDiscoverySet(selected)
}

func discoveryInstrumentationExecutedTargets(plan *discoveryOrdinarySelectionPlan) []string {
	selected := make(map[string]bool)
	if plan != nil && plan.InstrumentationPlan != nil {
		for _, outcome := range plan.InstrumentationPlan.Outcomes {
			if outcome.Status == "llvm_objects_only" && outcome.Error == "" && outcome.Objects != nil {
				selected[outcome.Objects.Target] = true
			}
		}
	}
	return sortedDiscoverySet(selected)
}

// Failed mode scopes remain failures, but their complete denominator and any
// partial observations must survive both report and ledger readback. In
// particular deleting all outcomes cannot silently erase an early rejection.
func validateDiscoveryInstrumentationFailure(result discoveryCorpusResult, inventory *discoveryFeatureInventory) error {
	if result.Status != discoveryStatusFailed || result.OrdinarySelectionPlan == nil {
		return nil
	}
	profiles, err := resolveDiscoveryFeatureProfiles(inventory, result.FeatureProfiles)
	if err != nil {
		return err
	}
	scope, err := discoveryResultAssemblyScope(result)
	if err != nil {
		return err
	}
	if _, _, err := validateDiscoveryInstrumentationResult(result, profiles, scope); err != nil {
		return fmt.Errorf("failed instrumentation scope readback: %w", err)
	}
	return nil
}

func validateDiscoveryInstrumentationToolProvenance(result discoveryCorpusResult, provenance discoveryCorpusProvenance) error {
	if result.OrdinarySelectionPlan == nil || result.OrdinarySelectionPlan.InstrumentationPlan == nil {
		if result.InstrumentationTranslations != 0 || result.InstrumentationTargetExclusions != 0 {
			return fmt.Errorf("mode object count has no independently required mode protocol")
		}
		return nil
	}
	if provenance.InstrumentationScopeProtocol == discoveryInstrumentationPlanProtocol &&
		result.OrdinarySelectionPlan.InstrumentationPlan.Protocol != discoveryInstrumentationPlanProtocol {
		return fmt.Errorf("current stamped producer cannot downgrade its instrumentation denominator")
	}
	if provenance.InstrumentationScopeProtocol == discoveryInstrumentationPlanProtocol && result.OrdinarySelectionPlan.GoVersion != provenance.GoVersion {
		return fmt.Errorf("current mode scope used another actual Go source/tool version")
	}
	if provenance.InstrumentationScopeProtocol == "" && result.InstrumentationTargetExclusions != 0 {
		return fmt.Errorf("historical producer cannot claim official mode-target exclusions")
	}
	for _, outcome := range result.OrdinarySelectionPlan.InstrumentationPlan.Outcomes {
		if outcome.Objects == nil {
			continue
		}
		tool := outcome.Objects.LLVM
		if tool == nil || tool.SHA256 != provenance.LLCBinarySHA256 {
			return fmt.Errorf("mode LLVM objects used a different actual compiler than the report provenance")
		}
		version := discoveryLLVMVersionPattern.FindStringSubmatch(tool.Version)
		if len(version) != 2 || version[1] != provenance.LLVMVersion {
			return fmt.Errorf("mode LLVM version differs from independently captured report tools")
		}
	}
	return nil
}
