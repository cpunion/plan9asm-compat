package main

import (
	"fmt"
	"path"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// A metadata query has no translation count. Its exact selected package and
// four-dimensional source-required scope are consumed independently later.
type discoveryGeneratedHeaderQuery struct {
	Target    string                       `json:"target"`
	ProfileID string                       `json:"profile_id"`
	BuildTags []string                     `json:"build_tags,omitempty"`
	AsmFiles  []string                     `json:"asm_files"`
	Metadata  *gotoolprofile.MetadataProof `json:"metadata"`
}

func ordinaryGeneratedMetadata(plan *discoveryOrdinarySelectionPlan, profileID string, files, tags []string) (*gotoolprofile.MetadataProof, error) {
	var found *gotoolprofile.MetadataProof
	for _, query := range plan.GeneratedHeaders {
		if query.ProfileID != profileID || !equalDiscoveryStrings(query.BuildTags, tags) {
			continue
		}
		matches := len(files) != 0
		for _, file := range files {
			matches = matches && containsTargetFeature(query.AsmFiles, file)
		}
		if matches {
			if found != nil {
				return nil, fmt.Errorf("generated header has duplicate producer query scopes")
			}
			found = query.Metadata
		}
	}
	return found, nil
}

func validateDiscoveryGeneratedHeaderQueries(plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile, eligible map[discoveryProfileScope]bool) error {
	if len(plan.GeneratedHeaders) > 4096 || len(plan.GeneratedGoSources) > 32768 {
		return fmt.Errorf("generated-header producer exceeds explicit scope/source bounds")
	}
	for file, digest := range plan.GeneratedGoSources {
		if !ordinarySelectionLocalPath(file) || !strings.HasSuffix(file, ".go") || !discoverySHA256Pattern.MatchString(digest) {
			return fmt.Errorf("generated-header imported Go source lacks an exact original identity")
		}
		for _, directory := range plan.Directories {
			if directory.Directory != path.Dir(file) {
				continue
			}
			for _, entry := range directory.Entries {
				if entry.Name == path.Base(file) && (entry.Kind != "file" || entry.SHA256 != digest) {
					return fmt.Errorf("generated-header Go snapshot conflicts with original directory/ZIP inputs")
				}
			}
		}
	}
	if len(plan.GeneratedGoSources) != 0 && len(plan.GeneratedHeaders) == 0 {
		return fmt.Errorf("imported generated-header source snapshot lacks actual metadata queries")
	}
	seen := make(map[discoveryProfileScope]bool)
	for _, query := range plan.GeneratedHeaders {
		var profile *discoveryFeatureProfile
		for index := range profiles {
			if profiles[index].ID == query.ProfileID {
				profile = &profiles[index]
			}
		}
		if profile == nil || query.Target != profile.Observed.Target || len(query.AsmFiles) == 0 || !equalDiscoveryStrings(query.AsmFiles, uniqueSortedDiscoveryStrings(query.AsmFiles)) || !equalDiscoveryStrings(query.BuildTags, uniqueSortedDiscoveryStrings(query.BuildTags)) {
			return fmt.Errorf("generated-header query lacks a canonical actual profile/file/tag scope")
		}
		for _, file := range query.AsmFiles {
			key := discoveryProfileScope{File: file, Target: query.Target, ProfileID: query.ProfileID, Tags: strings.Join(query.BuildTags, "\x00")}
			if !eligible[key] || seen[key] || path.Dir(file) != path.Dir(query.AsmFiles[0]) {
				return fmt.Errorf("generated-header query claims a duplicate/unselected package scope")
			}
			seen[key] = true
		}
		module, err := ordinaryProfileDeclaredModule(plan)
		if err != nil {
			return err
		}
		input := ordinaryProfileConsumerInput(plan, *profile, module, "", query.AsmFiles, query.BuildTags)
		input.GeneratedHeaders = nil
		if err := gotoolprofile.ValidateMetadata(input, query.Metadata, query.BuildTags); err != nil {
			return err
		}
		wantedPackage := module
		if directory := path.Dir(query.AsmFiles[0]); directory != "." {
			wantedPackage += "/" + directory
		}
		if len(query.Metadata.Packages) != 1 || query.Metadata.Packages[0].PackagePath != wantedPackage {
			return fmt.Errorf("generated metadata query expanded beyond its exact ordinary package role")
		}
	}
	return nil
}

func validateDiscoveryGeneratedHeaderExecution(plan *discoveryOrdinarySelectionPlan, executed map[discoveryProfileScope]bool) error {
	for _, query := range plan.GeneratedHeaders {
		if !discoveryCPPFilesNeedGeneratedMetadata(plan.CPPInputs, query.AsmFiles) {
			return fmt.Errorf("generated-header query has no raw generated origin in its executed package")
		}
		for _, file := range query.AsmFiles {
			key := discoveryProfileScope{File: file, Target: query.Target, ProfileID: query.ProfileID, Tags: strings.Join(query.BuildTags, "\x00")}
			if !executed[key] {
				return fmt.Errorf("metadata query cannot substitute for an unexecuted/rejected translation scope")
			}
		}
	}
	return nil
}
