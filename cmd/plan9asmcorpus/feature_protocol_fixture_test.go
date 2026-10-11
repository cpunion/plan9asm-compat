package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// These Go 1.27.1 baseline/registration bytes were captured with the real
// driver. Synthetic objects below test portable accounting only; they are not
// library, LLVM or runtime passes. Keeping this fixture portable also lets
// Go 1.20 test the schema reader without pretending to run the Go 1.27 gate.
type featureProtocolFixture struct {
	Observed map[string]*discoveryTargetFeatures       `json:"observed"`
	Macros   map[string]*gotoolprofile.AssemblerMacros `json:"macros"`
	CPP      *discoveryCPPRegistration                 `json:"cpp"`
}

var ordinaryFixtureRoots sync.Map

func fixtureProfileEvidence(t *testing.T, result *discoveryCorpusResult, inventory *discoveryFeatureInventory) {
	t.Helper()
	fixtureProfileEvidenceWithGeneratedHeaders(t, result, inventory, nil)
}

func fixtureProfileEvidenceWithGeneratedHeaders(t *testing.T, result *discoveryCorpusResult, inventory *discoveryFeatureInventory, headers map[string]*gotoolprofile.GeneratedHeaderProof) {
	t.Helper()
	data, err := os.ReadFile("testdata/go127_feature_protocol_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture featureProtocolFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	plan := result.OrdinarySelectionPlan
	plan.DocumentationSourceProtocol = discoveryDocumentationProtocol
	plan.CPPSourceProtocol = discoveryReplayCPPInputsProtocol
	var profiles []discoveryFeatureProfile
	byTarget := make(map[string]discoveryFeatureProfile)
	for _, target := range plan.Targets {
		observed := fixture.Observed[target]
		if observed == nil {
			t.Fatalf("no actually captured protocol baseline fixture for %s", target)
		}
		profile := discoveryFeatureProfile{ID: discoveryFeatureProfileID(observed), Observed: observed,
			Request: discoveryFeatureProfileRequest{Target: target, Baseline: true}}
		profiles = append(profiles, profile)
		byTarget[target] = profile
	}
	sort.Slice(profiles, func(i, j int) bool {
		return discoveryFeatureRequestKey(profiles[i].Request) < discoveryFeatureRequestKey(profiles[j].Request)
	})
	result.FeatureProfiles, err = registerDiscoveryFeatureProfiles(inventory, profiles)
	if err != nil {
		t.Fatal(err)
	}
	result.featureInventory = inventory
	var baselines []*discoveryTargetFeatures
	for _, profile := range profiles {
		baselines = append(baselines, profile.Observed)
	}
	if err := captureDiscoveryInstrumentationDenominator(plan, result.DiscoveredAsmFiles, baselines); err != nil {
		t.Fatal(err)
	}
	decisions, eligible, err := replayOrdinarySelectionForProfiles(plan, result.DiscoveredAsmFiles, profiles)
	if err != nil {
		t.Fatal(err)
	}
	plan.ProfileDecisions = decisions
	files := ordinaryProfileEligibleCPPFiles(eligible)
	if len(files) != 0 {
		root, found := ordinaryFixtureRoots.Load(plan)
		if !found {
			t.Fatal("synthetic protocol fixture lost its original source directory")
		}
		inputs := &discoveryCPPInputs{Protocol: discoveryReplayCPPInputsProtocol,
			Module: plan.Module, Version: plan.Version, ModuleSum: plan.ModuleSum, ZipSHA256: plan.ZipSHA256,
			Registration: fixture.CPP, Sources: make(map[string]discoveryCPPSource)}
		for _, file := range files {
			contents, err := os.ReadFile(filepath.Join(root.(string), filepath.FromSlash(file)))
			if err != nil {
				t.Fatal(err)
			}
			source, err := discoveryReplayCPPSource(file, contents)
			if err != nil {
				t.Fatal(err)
			}
			inputs.Sources["module/"+file] = source
			unit := discoveryCPPUnit{File: file}
			if header := headers[file]; header != nil {
				unit.DeferredIncludes = make(map[string]string)
				for index, directive := range source.Directives {
					if directive.Kind == "include" && directive.Include == "go_asm.h" {
						key := fmt.Sprintf("module/%s#%d", file, index)
						unit.DeferredIncludes[key] = "generated_go_asm"
					}
				}
				if len(unit.DeferredIncludes) == 0 {
					t.Fatalf("generated accounting header has no original include edge: %s", file)
				}
			}
			inputs.Units = append(inputs.Units, unit)
		}
		plan.CPPInputs = inputs
	}
	profileMacros := make(map[string]*gotoolprofile.AssemblerMacros)
	for _, profile := range profiles {
		profileMacros[profile.ID] = fixture.Macros[profile.Observed.Target]
	}
	if len(headers) != 0 {
		// Deferred native headers preserve the full legal CPU denominator.
		// Consume actual captured variants instead of modeling their evidence
		// or supplying a fabricated header to narrow the planner's requests.
		requests, err := planDiscoveryFeatureProfiles(plan, result.DiscoveredAsmFiles, baselines)
		if err != nil {
			t.Fatal(err)
		}
		profiles, profileMacros = fixtureProfileCPUProposals(t, fixture, requests)
		result.FeatureProfiles, err = registerDiscoveryFeatureProfiles(inventory, profiles)
		if err != nil {
			t.Fatal(err)
		}
		decisions, eligible, err = replayOrdinarySelectionForProfiles(plan, result.DiscoveredAsmFiles, profiles)
		if err != nil {
			t.Fatal(err)
		}
		plan.ProfileDecisions = decisions
		result.BuildConfigurations = ordinaryProfileConfigurations(eligible)
		result.Translations = len(eligible)
	}
	var configs []discoveryBuildConfiguration
	for _, config := range result.BuildConfigurations {
		if len(headers) != 0 {
			configs = append(configs, config)
			continue
		}
		for _, target := range config.Targets {
			configs = append(configs, discoveryBuildConfiguration{
				ProfileID: byTarget[target].ID, BuildTags: config.BuildTags,
				Targets: []string{target}, AsmFiles: config.AsmFiles,
			})
		}
	}
	result.BuildConfigurations = configs
	var sourceItems []discoverySourceNotApplicableItem
	for _, item := range result.SourceNotApplicableItems {
		for _, target := range item.Targets {
			copy := item
			copy.ProfileID, copy.Targets = byTarget[target].ID, []string{target}
			sourceItems = append(sourceItems, copy)
		}
	}
	result.SourceNotApplicableItems = sourceItems
	result.FeatureConsumption = nil
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	for _, config := range configs {
		profile := byProfile[config.ProfileID]
		module, err := ordinaryProfileDeclaredModule(plan)
		if err != nil {
			t.Fatal(err)
		}
		input := ordinaryProfileConsumerInput(plan, profile, module, "", config.AsmFiles, config.BuildTags)
		proof := &gotoolprofile.SelectionProof{
			SignatureSourceProtocol:      gotoolprofile.SignatureSourceProtocol,
			TestDependencySourceProtocol: gotoolprofile.TestDependencyProtocol,
			CPPSourceProtocol:            input.CPPSourceProtocol,
			CPPIncludeSearchMisses:       append([]gotoolprofile.CPPPackageSearchMiss(nil), input.CPPIncludeSearchMisses...),
			Protocol:                     gotoolprofile.ConsumerProtocol, ProfileID: profile.ID, CustomTags: config.BuildTags,
			RegisteredAsmFiles: append([]string(nil), input.RegisteredAsmFiles...),
		}
		ctx, err := discoveryContextForFeatureProfile(profile.Observed)
		if err != nil {
			t.Fatal(err)
		}
		ctx.BuildTags = config.BuildTags
		byDirectory := make(map[string][]string)
		for _, file := range config.AsmFiles {
			signature := gotoolprofile.SignatureSource{
				Symbol: module + ".accounting_" + discoveryFeatureBytesSHA256([]byte(file))[:16],
				Role:   "asm_fallback", LayoutSHA256: strings.Repeat("5", 64),
			}
			byDirectory[path.Dir(file)] = append(byDirectory[path.Dir(file)], file)
			var unit discoveryCPPUnit
			for _, registered := range plan.CPPInputs.Units {
				if registered.File == file {
					unit = registered
					break
				}
			}
			observation, consumed, err := replayDiscoveryOriginalCPP(plan.CPPInputs, unit, headers[file],
				profileMacros[profile.ID].Defines)
			if err != nil {
				t.Fatalf("replay original portable accounting CPP %s: %v", file, err)
			}
			// Even an empty active set comes from complete original execution.
			// A null set is incomplete evidence, not a source exclusion or pass.
			expandedOperands, err := gotoolprofile.CPPExpandedOperands(input, file, observation)
			if err != nil {
				t.Fatalf("observe original portable accounting operands %s: %v", file, err)
			}
			proof.CPP = append(proof.CPP, gotoolprofile.CPPProof{File: file, Emission: "assembly",
				ExpandedSHA256:       discoveryFeatureBytesSHA256([]byte(observation.Output)),
				TypedExpandedSHA256:  strings.Repeat("2", 64),
				ExpandedSearchMisses: expandedOperands,
				Inputs:               consumed, Signatures: []gotoolprofile.SignatureSource{signature}})
			proof.Outputs = append(proof.Outputs, gotoolprofile.OutputProof{
				File: file, Part: path.Base(file) + ".ll", IR: strings.Repeat("3", 64), Object: strings.Repeat("4", 64),
			})
		}
		for _, dir := range sortedFixtureDirectories(byDirectory) {
			if input.RegisteredAsmFiles != nil {
				byDirectory[dir] = nil
				for _, file := range input.RegisteredAsmFiles {
					if path.Dir(file) == dir {
						byDirectory[dir] = append(byDirectory[dir], file)
					}
				}
			}
			pkgPath := module
			if dir != "." {
				pkgPath += "/" + dir
			}
			macros := *profileMacros[profile.ID]
			macros.PackagePath = pkgPath
			pkg := gotoolprofile.PackageProof{
				PackagePath: pkgPath, ModulePath: module, ModuleVersion: plan.Version,
				SourceModule: plan.Module, SourceVersion: plan.Version, SourceRole: "module",
				SFiles: byDirectory[dir], SourceSHA256: make(map[string]string), Macros: &macros,
			}
			for _, source := range plan.Sources {
				if path.Dir(source.File) != dir || !strings.HasSuffix(source.File, ".go") || strings.HasSuffix(source.File, "_test.go") {
					continue
				}
				ctx.OpenFile = fixtureHeaderOpener(plan)
				selected, err := ctx.MatchFile(dir, path.Base(source.File))
				if err != nil {
					t.Fatal(err)
				}
				if selected {
					pkg.GoFiles = append(pkg.GoFiles, source.File)
					pkg.SourceSHA256[source.File] = input.Sources[source.File]
				}
			}
			pkg.CompiledGoFiles = append([]string(nil), pkg.GoFiles...)
			for _, file := range pkg.SFiles {
				pkg.SourceSHA256[file] = input.Sources[file]
			}
			proof.Packages = append(proof.Packages, pkg)
		}
		result.FeatureConsumption = append(result.FeatureConsumption, proof)
	}
}

func sortedFixtureDirectories(dirs map[string][]string) []string {
	set := make(map[string]bool)
	for dir := range dirs {
		set[dir] = true
	}
	return sortedDiscoverySet(set)
}

func fixtureHeaderOpener(plan *discoveryOrdinarySelectionPlan) func(string) (io.ReadCloser, error) {
	return func(file string) (io.ReadCloser, error) {
		for _, source := range plan.Sources {
			if source.File == filepath.ToSlash(file) {
				return io.NopCloser(strings.NewReader(source.Header)), nil
			}
		}
		return nil, fmt.Errorf("uncaptured fixture source %s", file)
	}
}

func fixtureProfileMatrix(t *testing.T, result discoveryCorpusResult) matrixReport {
	t.Helper()
	profiles, err := resolveDiscoveryFeatureProfiles(result.featureInventory, result.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	return matrixReport{Success: result.Translations, TotalTargets: len(result.OrdinarySelectionPlan.Targets),
		OrdinarySelectionPlan: result.OrdinarySelectionPlan,
		FeatureProfiles:       profiles, FeatureConsumption: result.FeatureConsumption}
}
