package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// Resolve only the exact already authenticated root into this new owned
// invocation's go.sum. A missing sum entry is setup failure, never compiler
// source rejection; source and configuration guards begin after this step.
func prepareDiscoveryInstrumentationRejectedModule(ctx context.Context, binary, directory string, env []string, modulePath string, expected moduleDownloadInfo) error {
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, directory, env, binary, "mod", "download", "-json", modulePath)
	if err != nil || len(stderr) != 0 {
		return fmt.Errorf("actual rejected-mode exact module setup: %v; %s", err, stderr)
	}
	var actual moduleDownloadInfo
	if err := json.Unmarshal(stdout, &actual); err != nil || actual.Error != "" || actual.Path != expected.Path || actual.Version != expected.Version ||
		actual.Sum != expected.Sum || actual.GoModSum != expected.GoModSum || actual.Sum == "" || actual.GoModSum == "" {
		return fmt.Errorf("rejected-mode setup changed the original exact module/checksums: %v", err)
	}
	root, err := filepath.EvalSymlinks(actual.Dir)
	original, originalErr := filepath.EvalSymlinks(expected.Dir)
	if err != nil || originalErr != nil || root != original {
		return fmt.Errorf("rejected-mode setup changed the original exact archive root")
	}
	for _, pair := range [][2]string{{actual.GoMod, expected.GoMod}, {actual.Zip, expected.Zip}} {
		left, leftErr := gotoolprofile.FileSHA256(pair[0])
		right, rightErr := gotoolprofile.FileSHA256(pair[1])
		if leftErr != nil || rightErr != nil || left != right {
			return fmt.Errorf("rejected-mode setup changed original metadata/archive bytes")
		}
	}
	return nil
}

func validateDiscoveryInstrumentationSourceRejection(plan *discoveryOrdinarySelectionPlan, requirement discoveryInstrumentationRequirement, outcome discoveryInstrumentationOutcome, profiles []discoveryFeatureProfile) (*gotoolprofile.InstrumentationOriginalPackagePlan, error) {
	if plan.InstrumentationPlan.Protocol != discoveryInstrumentationPlanProtocol || outcome.Status != discoveryInstrumentationSourceRejectedStatus ||
		outcome.Stage != "original_source_rejection" || outcome.Error != "" || outcome.Early != nil || outcome.TargetExclusion != nil ||
		outcome.TypeSources != nil || outcome.Query != nil || outcome.Objects != nil || outcome.PackagePlan == nil {
		return nil, fmt.Errorf("original source rejection cannot carry target rules, failures, exports or LLVM objects")
	}
	observed := plan.InstrumentationPlan.Observations[outcome.ObservationID]
	if observed == nil || outcome.ObservationID != gotoolprofile.InstrumentationEarlyProfileID(observed.Early) {
		return nil, fmt.Errorf("original mode rejection has a missing or substituted actual observation")
	}
	if err := validateDiscoveryInstrumentationObservation(requirement, profiles, observed); err != nil {
		return nil, err
	}
	if err := validateDiscoveryInstrumentationExclusionSources(plan, requirement, observed.Early); err != nil {
		return nil, err
	}
	inventory := plan.InstrumentationPlan.Sources[requirement.Directory]
	input := discoveryInstrumentationOriginalInput(plan, observed, "/original-offline-source", nil)
	packagePlan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observed.Early, requirement.Directory, requirement.Tags)
	if err != nil {
		return nil, err
	}
	input.AsmFiles = append([]string(nil), packagePlan.SFiles...)
	packagePlan, err = gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observed.Early, requirement.Directory, requirement.Tags)
	if err != nil || !reflect.DeepEqual(packagePlan, outcome.PackagePlan) {
		return nil, fmt.Errorf("original source rejection changed its complete independent mode selection: %v", err)
	}
	if err := gotoolprofile.ValidateInstrumentationSourceRejection(input, inventory, observed, packagePlan, outcome.SourceRejection); err != nil {
		return nil, err
	}
	return packagePlan, nil
}

func discoveryInstrumentationSourceRejections(plan *discoveryOrdinarySelectionPlan) int {
	count := 0
	if plan != nil && plan.InstrumentationPlan != nil {
		for _, outcome := range plan.InstrumentationPlan.Outcomes {
			if outcome.Status == discoveryInstrumentationSourceRejectedStatus {
				count++
			}
		}
	}
	return count
}
