package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func validateDiscoveryInstrumentationTargetExclusion(plan *discoveryOrdinarySelectionPlan, requirement discoveryInstrumentationRequirement, outcome discoveryInstrumentationOutcome, profiles []discoveryFeatureProfile) error {
	if plan.InstrumentationPlan.Protocol != discoveryInstrumentationPlanProtocol || outcome.Status != discoveryInstrumentationExcludedStatus ||
		outcome.Stage != "early_rules" || outcome.Error != "" || outcome.Early != nil ||
		outcome.ObservationID != "" || outcome.PackagePlan != nil || outcome.TypeSources != nil || outcome.Query != nil || outcome.Objects != nil || outcome.SourceRejection != nil {
		return fmt.Errorf("official target exclusion cannot carry failure/export/LLVM completion or a legacy protocol")
	}
	if err := gotoolprofile.ValidateInstrumentationTargetExclusion(outcome.TargetExclusion, requirement.Tags); err != nil {
		return err
	}
	if err := validateDiscoveryInstrumentationExclusionSources(plan, requirement, outcome.TargetExclusion.Early); err != nil {
		return err
	}
	return validateDiscoveryInstrumentationEarlyBinding(requirement, profiles, outcome.TargetExclusion.Early)
}

func validateDiscoveryInstrumentationExclusionSources(plan *discoveryOrdinarySelectionPlan, requirement discoveryInstrumentationRequirement, early *gotoolprofile.InstrumentationEarlyObservation) error {
	if plan.GoVersion != early.SourceRules.GoVersion {
		return fmt.Errorf("official target rule has another original source/tool version")
	}
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(plan.ModuleSum, "h1:"))
	if !discoverySHA256Pattern.MatchString(plan.ZipSHA256) || !strings.HasPrefix(plan.ModuleSum, "h1:") || err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("official target exclusion lacks its original ZIP/h1 identity")
	}
	if err := validateDiscoveryProxyGoMod(plan); err != nil {
		return err
	}
	if _, _, err := ordinarySelectionBytes(plan); err != nil {
		return err
	}
	inventory := plan.InstrumentationPlan.Sources[requirement.Directory]
	input := discoveryInstrumentationBaselineInput(plan, early.BaselineFeatures, "/original-offline-source", nil)
	if err := gotoolprofile.ValidateInstrumentationOriginalSourceInventory(input, requirement.Directory, inventory); err != nil {
		return err
	}
	for _, source := range plan.Sources {
		if source.File == "go.mod" && source.SHA256 != source.HeaderSHA256 {
			return fmt.Errorf("official target rule original go.mod bytes changed")
		}
		if path.Dir(source.File) != requirement.Directory || path.Ext(source.File) != ".go" && path.Ext(source.File) != ".s" {
			continue
		}
		body := []byte(inventory.Contents[source.File])
		var header string
		if path.Ext(source.File) == ".s" || source.PackageDiagnostic == "" {
			original, err := nativeLayoutSourceInputFromBytes(source.File, body)
			if err != nil {
				return err
			}
			header = original.Header
		} else {
			if len(body) > 64<<10 {
				body = body[:64<<10]
			}
			header = string(body)
		}
		if source.Header != compactOrdinarySelectionHeader(header) {
			return fmt.Errorf("official target rule source predicate differs from full original bytes: %s", source.File)
		}
	}
	return nil
}

func discoveryInstrumentationTargetExclusions(plan *discoveryOrdinarySelectionPlan) int {
	count := 0
	if plan != nil && plan.InstrumentationPlan != nil {
		for _, outcome := range plan.InstrumentationPlan.Outcomes {
			if outcome.Status == discoveryInstrumentationExcludedStatus {
				count++
			}
		}
	}
	return count
}
