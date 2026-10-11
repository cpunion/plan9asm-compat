package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

const discoveryInstrumentationHeaderPlanningProtocol = "same_mode_native_header_planning_query_v1"

// These observations are independent planning inputs, not executed outcomes or
// object observations. Full original/dependency bytes are shared once by digest.
type discoveryInstrumentationHeaderPlanning struct {
	Protocol string                                 `json:"protocol"`
	Rules    *gotoolprofile.NativeHeaderSourceRules `json:"rules"`
	Contents map[string]string                      `json:"original_contents"`
	Queries  []discoveryInstrumentationHeaderQuery  `json:"queries"`
	used     map[string]bool
}

type discoveryInstrumentationHeaderQuery struct {
	Requirement    discoveryInstrumentationRequirement                   `json:"request"`
	Assembly       string                                                `json:"assembly"`
	Observation    *gotoolprofile.InstrumentationExportObservation       `json:"actual_mode_observation"`
	PackagePlan    *gotoolprofile.InstrumentationOriginalPackagePlan     `json:"original_package_plan"`
	Signatures     discoveryInstrumentationHeaderTypes                   `json:"signature_sources"`
	Properties     *gotoolprofile.InstrumentationNativeHeaderSourceProof `json:"property_sources"`
	PropertyTypes  discoveryInstrumentationHeaderTypes                   `json:"property_type_contents"`
	ModuleMetadata map[string]string                                     `json:"module_metadata_contents"`
	Metadata       *gotoolprofile.InstrumentationMetadataProof           `json:"actual_metadata"`
}

// Complete dependency files are referenced once by their original source hash.
// Module selection headers remain the existing compact projections in Proof;
// they are not full files and must not be compared to full-file source hashes.
type discoveryInstrumentationHeaderTypes struct {
	Proof    *gotoolprofile.InstrumentationTypeSourceProof `json:"proof"`
	Packages map[string]map[string]string                  `json:"package_contents"`
}

func instrumentationHeaderQueryKey(requirement discoveryInstrumentationRequirement, assembly string) (string, error) {
	key, err := instrumentationRequirementKey(requirement)
	return assembly + "\x00" + key, err
}

func compactInstrumentationHeaderTypes(role *discoveryInstrumentationHeaderPlanning, proof *gotoolprofile.InstrumentationTypeSourceProof) (discoveryInstrumentationHeaderTypes, error) {
	data, err := json.Marshal(proof)
	if err != nil {
		return discoveryInstrumentationHeaderTypes{}, err
	}
	var copy gotoolprofile.InstrumentationTypeSourceProof
	if err := json.Unmarshal(data, &copy); err != nil {
		return discoveryInstrumentationHeaderTypes{}, err
	}
	result := discoveryInstrumentationHeaderTypes{Proof: &copy, Packages: make(map[string]map[string]string)}
	for index := range copy.Dependencies {
		dependency := &copy.Dependencies[index]
		if dependency.Contents != nil {
			result.Packages[dependency.Dependency.Source.PackagePath] = retainInstrumentationHeaderContents(role, dependency.Contents)
			dependency.Contents = nil
		}
	}
	return result, nil
}

func retainInstrumentationHeaderContents(role *discoveryInstrumentationHeaderPlanning, contents map[string]string) map[string]string {
	if contents == nil {
		return nil
	}
	refs := make(map[string]string)
	for name, text := range contents {
		digest := discoveryFeatureBytesSHA256([]byte(text))
		role.Contents[digest] = text
		refs[name] = digest
	}
	return refs
}

func restoreInstrumentationHeaderContents(role *discoveryInstrumentationHeaderPlanning, refs, expected map[string]string) (map[string]string, error) {
	if refs == nil || len(refs) > 32768 {
		return nil, fmt.Errorf("native mode query content references are missing or unbounded")
	}
	result := make(map[string]string)
	for name, digest := range refs {
		text, present := role.Contents[digest]
		if !present || expected[name] != digest || discoveryFeatureBytesSHA256([]byte(text)) != digest {
			return nil, fmt.Errorf("native mode query content differs from its original source anchor")
		}
		result[name] = text
	}
	return result, nil
}

func restoreInstrumentationHeaderTypes(role *discoveryInstrumentationHeaderPlanning, compact discoveryInstrumentationHeaderTypes) (*gotoolprofile.InstrumentationTypeSourceProof, error) {
	if compact.Proof == nil || compact.Packages == nil || len(compact.Packages) > 8192 {
		return nil, fmt.Errorf("native mode property query lost its bounded source references")
	}
	data, err := json.Marshal(compact.Proof)
	if err != nil {
		return nil, err
	}
	var proof gotoolprofile.InstrumentationTypeSourceProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}
	usedPackages := 0
	for index := range proof.Dependencies {
		dependency := &proof.Dependencies[index]
		if dependency.Contents != nil {
			return nil, fmt.Errorf("compact native query invented inline dependency bytes")
		}
		if refs, present := compact.Packages[dependency.Dependency.Source.PackagePath]; present {
			dependency.Contents, err = restoreInstrumentationHeaderContents(role, refs, dependency.Dependency.Source.GoSHA256)
			if err != nil {
				return nil, err
			}
			usedPackages++
		}
	}
	for _, module := range proof.SourceModules {
		for name, digest := range module.Sources {
			if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".s") {
				continue
			}
			text, present := role.Contents[digest]
			if !present {
				continue // Unneeded source-only members retain the existing v2 role.
			}
			header, err := gotoolprofile.TestSelectionHeader(name, []byte(text))
			if err != nil || module.Headers[name] != header {
				return nil, fmt.Errorf("native query selection projection differs from complete selected source bytes: %v", err)
			}
		}
	}
	if usedPackages != len(compact.Packages) {
		return nil, fmt.Errorf("native mode query has unconsumed package source references")
	}
	return &proof, nil
}

func discoveryInstrumentationPlanningHeader(plan *discoveryOrdinarySelectionPlan, requirement discoveryInstrumentationRequirement, assembly string, baselines []*discoveryTargetFeatures) (*gotoolprofile.GeneratedHeaderProof, error) {
	if capture := plan.InstrumentationPlan.headerPlanningCapture; capture != nil {
		return capture(requirement, assembly)
	}
	return replayDiscoveryInstrumentationPlanningHeader(plan, requirement, assembly, baselines)
}

func replayDiscoveryInstrumentationPlanningHeader(plan *discoveryOrdinarySelectionPlan, requirement discoveryInstrumentationRequirement, assembly string, baselines []*discoveryTargetFeatures) (*gotoolprofile.GeneratedHeaderProof, error) {
	proof := plan.InstrumentationPlan
	role := proof.HeaderPlanning
	if role == nil || role.Protocol != discoveryInstrumentationHeaderPlanningProtocol || role.Contents == nil || len(role.Contents) > 32768 || len(role.Queries) == 0 || len(role.Queries) > 4096 {
		return nil, fmt.Errorf("same-mode planning query is absent, downgraded or unbounded")
	}
	if err := gotoolprofile.ValidateNativeHeaderSourceRules(role.Rules, plan.GoVersion); err != nil {
		return nil, err
	}
	key, err := instrumentationHeaderQueryKey(requirement, assembly)
	if err != nil {
		return nil, err
	}
	var found *discoveryInstrumentationHeaderQuery
	for index := range role.Queries {
		query := &role.Queries[index]
		other, err := instrumentationHeaderQueryKey(query.Requirement, query.Assembly)
		if err != nil {
			return nil, err
		}
		if key == other {
			if found != nil {
				return nil, fmt.Errorf("duplicate same-mode native header query")
			}
			found = query
		}
	}
	if found == nil || found.Properties == nil || found.Properties.Types != nil || found.Properties.GoMods != nil {
		return nil, fmt.Errorf("same-mode native query lost its exact request or compact property role")
	}
	var profiles []discoveryFeatureProfile
	for _, baseline := range baselines {
		profiles = append(profiles, discoveryFeatureProfile{ID: discoveryFeatureProfileID(baseline), Observed: baseline,
			Request: discoveryFeatureProfileRequest{Target: baseline.Target, Baseline: true}})
	}
	if err := validateDiscoveryInstrumentationObservation(requirement, profiles, found.Observation); err != nil {
		return nil, err
	}
	// Same unopened portable root as the existing outcome reader. Physical
	// invocation paths are excluded from the input SHA, never authenticated here.
	input := discoveryInstrumentationOriginalInput(plan, found.Observation, "/original-offline-source", nil)
	inventory := proof.Sources[requirement.Directory]
	packagePlan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, found.Observation.Early, requirement.Directory, requirement.Tags)
	if err != nil {
		return nil, err
	}
	input.AsmFiles = append([]string(nil), packagePlan.SFiles...)
	packagePlan, err = gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, found.Observation.Early, requirement.Directory, requirement.Tags)
	if err != nil || !reflect.DeepEqual(packagePlan, found.PackagePlan) || !containsTargetFeature(packagePlan.SFiles, assembly) {
		return nil, fmt.Errorf("same-mode planning selection differs from original source replay: %v", err)
	}
	wrapped, err := gotoolprofile.NewInstrumentationConsumerInput(input, inventory, found.Observation, packagePlan)
	if err != nil {
		return nil, err
	}
	wrapped.TypeSources, err = restoreInstrumentationHeaderTypes(role, found.Signatures)
	if err != nil {
		return nil, err
	}
	if err := gotoolprofile.ValidateInstrumentationMetadata(wrapped, requirement.Directory, requirement.Tags, found.Metadata); err != nil {
		return nil, err
	}
	properties := *found.Properties
	properties.Types, err = restoreInstrumentationHeaderTypes(role, found.PropertyTypes)
	if err != nil {
		return nil, err
	}
	moduleHashes := map[string]string{"original": wrapped.Original.Sources["go.mod"]}
	if wrapped.Original.ProxyGoMod != nil {
		moduleHashes["original"] = wrapped.Original.ProxyGoMod.SHA256
	}
	for _, module := range properties.Types.SourceModules {
		moduleHashes[module.ID()] = module.GoModSHA256
	}
	properties.GoMods, err = restoreInstrumentationHeaderContents(role, found.ModuleMetadata, moduleHashes)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(properties.Types.RootImportMap, wrapped.TypeSources.RootImportMap) {
		return nil, fmt.Errorf("same-mode property and signature queries differ in original imports")
	}
	dependencies := make([]gotoolprofile.InstrumentationDependencyExport, 0, len(properties.Types.Dependencies))
	for _, dependency := range properties.Types.Dependencies {
		dependencies = append(dependencies, dependency.Dependency)
	}
	if !reflect.DeepEqual(dependencies, found.Metadata.Dependencies) {
		return nil, fmt.Errorf("same-mode property graph differs from actual metadata exports/source")
	}
	definitions, language, err := gotoolprofile.ReplayInstrumentationNativeGeneratedHeader(wrapped, &properties)
	if err != nil {
		return nil, err
	}
	header := found.Metadata.Headers[0].Header
	if language != header.LanguageVersion || !reflect.DeepEqual(definitions, header.Definitions) {
		return nil, fmt.Errorf("same-mode native header differs from independent original property replay")
	}
	if role.used != nil {
		role.used[key] = true
	}
	return &header, nil
}

func validateDiscoveryInstrumentationHeaderPlanningConsumption(role *discoveryInstrumentationHeaderPlanning) error {
	if role == nil {
		return nil
	}
	seen, usedContents := make(map[string]bool), make(map[string]bool)
	for _, query := range role.Queries {
		key, err := instrumentationHeaderQueryKey(query.Requirement, query.Assembly)
		if err != nil || seen[key] || !role.used[key] {
			return fmt.Errorf("duplicate or unconsumed same-mode native planning query")
		}
		seen[key] = true
		for _, compact := range []discoveryInstrumentationHeaderTypes{query.Signatures, query.PropertyTypes} {
			for _, refs := range compact.Packages {
				for _, digest := range refs {
					usedContents[digest] = true
				}
			}
		}
		for _, digest := range query.ModuleMetadata {
			usedContents[digest] = true
		}
	}
	var total int
	for digest, text := range role.Contents {
		total += len(text)
		if !usedContents[digest] || len(text) > 2<<20 || total > 16<<20 || discoveryFeatureBytesSHA256([]byte(text)) != digest {
			return fmt.Errorf("same-mode native planning content is extra, changed or unbounded")
		}
	}
	if len(seen) == 0 || len(usedContents) != len(role.Contents) {
		return fmt.Errorf("same-mode native planning has missing or unconsumed source bytes")
	}
	return nil
}
