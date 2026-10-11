package main

import (
	"fmt"
	"path"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type discoveryTestDeclarationQuery struct {
	Target     string                             `json:"target"`
	ProfileID  string                             `json:"profile_id"`
	BuildTags  []string                           `json:"build_tags,omitempty"`
	AsmFiles   []string                           `json:"asm_files"`
	Dependency *gotoolprofile.TestDependencyProof `json:"dependency"`
}

func ordinaryTestDependencies(plan *discoveryOrdinarySelectionPlan, profileID string, files, tags []string) (*gotoolprofile.TestDependencyProof, error) {
	var found *gotoolprofile.TestDependencyProof
	for _, query := range plan.TestDeclarationQueries {
		if query.ProfileID == profileID && equalDiscoveryStrings(query.BuildTags, tags) && equalDiscoveryStrings(query.AsmFiles, files) {
			if found != nil {
				return nil, fmt.Errorf("duplicate missing-signature preflight/source closure")
			}
			found = query.Dependency
		}
	}
	return found, nil
}

func validateDiscoveryTestDeclarationQueries(plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile, eligible map[discoveryProfileScope]bool) error {
	if len(plan.TestDeclarationQueries) > 4096 || len(plan.TestDeclarationSources) > 32768 || len(plan.TestDeclarationDirectories) > 4096 {
		return fmt.Errorf("test declaration pre-load inventory exceeds explicit bounds")
	}
	copyPlan := *plan
	copyPlan.Sources = plan.TestDeclarationSources
	copyPlan.Directories = append(append([]ordinarySelectionDirectory(nil), plan.Directories...), plan.TestDeclarationDirectories...)
	if _, _, err := ordinarySelectionBytes(&copyPlan); err != nil {
		return fmt.Errorf("test declaration source-only inventory: %w", err)
	}
	ordinaryDirs := make(map[string]bool)
	headers := make(map[string]bool)
	for _, dir := range plan.Directories {
		ordinaryDirs[dir.Directory] = true
	}
	for _, source := range plan.Sources {
		headers[source.File] = true
	}
	for _, source := range plan.TestDeclarationSources {
		if headers[source.File] || !strings.HasSuffix(source.File, ".go") && !strings.HasSuffix(source.File, ".s") {
			return fmt.Errorf("test source-only header impersonates ordinary or non-selection source")
		}
		headers[source.File] = true
	}
	usedDirs := make(map[string]bool)
	seen := make(map[discoveryProfileScope]bool)
	for _, query := range plan.TestDeclarationQueries {
		var profile *discoveryFeatureProfile
		for index := range profiles {
			if profiles[index].ID == query.ProfileID {
				profile = &profiles[index]
			}
		}
		if profile == nil || query.Target != profile.Observed.Target || len(query.AsmFiles) == 0 ||
			!equalDiscoveryStrings(query.AsmFiles, uniqueSortedDiscoveryStrings(query.AsmFiles)) ||
			!equalDiscoveryStrings(query.BuildTags, uniqueSortedDiscoveryStrings(query.BuildTags)) || query.Dependency == nil ||
			query.Dependency.Protocol != gotoolprofile.TestDependencyProtocol || query.Dependency.Query == nil || len(query.Dependency.Query.Requests) == 0 {
			return fmt.Errorf("test declaration query lacks canonical actual source/profile/module scope")
		}
		for _, file := range query.AsmFiles {
			key := discoveryProfileScope{File: file, Target: query.Target, ProfileID: query.ProfileID, Tags: strings.Join(query.BuildTags, "\x00")}
			if !eligible[key] || seen[key] || path.Dir(file) != path.Dir(query.AsmFiles[0]) {
				return fmt.Errorf("test declaration query expanded/duplicated its eligible package scope")
			}
			seen[key] = true
		}
		module, err := ordinaryProfileDeclaredModule(plan)
		if err != nil {
			return err
		}
		input := ordinaryProfileConsumerInput(plan, *profile, module, "", query.AsmFiles, query.BuildTags)
		if err := gotoolprofile.ValidateTestDependencyPreload(input, query.Dependency, query.BuildTags); err != nil {
			return err
		}
		for _, source := range query.Dependency.Packages {
			dir := strings.TrimPrefix(strings.TrimPrefix(source.Package.PackagePath, module), "/")
			if dir == "" {
				dir = "."
			}
			for ; ; dir = path.Dir(dir) {
				usedDirs[dir] = true
				if dir == "." {
					break
				}
			}
		}
	}
	for _, dir := range plan.TestDeclarationDirectories {
		if ordinaryDirs[dir.Directory] || !usedDirs[dir.Directory] {
			return fmt.Errorf("test source-only inventory impersonates ordinary or unrelated directory")
		}
	}
	for _, source := range plan.TestDeclarationSources {
		if !usedDirs[path.Dir(source.File)] {
			return fmt.Errorf("test source-only header belongs to an unrelated directory")
		}
	}
	for _, dir := range copyPlan.Directories {
		if !usedDirs[dir.Directory] {
			continue
		}
		for _, entry := range dir.Entries {
			file := path.Join(dir.Directory, entry.Name)
			if entry.Kind == "file" && (strings.HasSuffix(file, ".go") || strings.HasSuffix(file, ".s")) {
				if !headers[file] {
					return fmt.Errorf("test source-only inventory omits a directory selection header")
				}
			}
		}
	}
	if len(plan.TestDeclarationQueries) == 0 && (len(plan.TestDeclarationSources) != 0 || len(plan.TestDeclarationDirectories) != 0) {
		return fmt.Errorf("test source-only inventory lacks a consumed missing-reference query")
	}
	return nil
}

func validateDiscoveryTestDeclarationExecution(plan *discoveryOrdinarySelectionPlan, executed map[discoveryProfileScope]bool) error {
	for _, query := range plan.TestDeclarationQueries {
		for _, file := range query.AsmFiles {
			if !executed[discoveryProfileScope{File: file, Target: query.Target, ProfileID: query.ProfileID, Tags: strings.Join(query.BuildTags, "\x00")}] {
				return fmt.Errorf("missing-signature query cannot replace original translation/object execution")
			}
		}
	}
	return nil
}
