package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestOrdinaryProfileResultRequiresAllFourScopeDimensions(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.com/vector", Version: "v1.0.0", AsmFiles: []string{"vector_amd64.s"}}
	plan := fixtureOrdinarySelectionForCandidate(t, candidate, []string{"linux/amd64"}, map[string]string{
		"go.mod":         "module example.com/vector\n",
		"vector_amd64.s": "//go:build amd64.v3\n\nTEXT ·probe(SB),$0-0\nRET\n",
		"vector.go":      "//go:build amd64.v3\n\npackage vector\nfunc probe()\n",
	})
	plan.GoVersion = runtime.Version()
	minor, err := discoveryGoMinor(plan.GoVersion)
	if err != nil {
		t.Fatal(err)
	}
	plan.ReleaseTags = nil
	for version := 1; version <= minor; version++ {
		plan.ReleaseTags = append(plan.ReleaseTags, fmt.Sprintf("go1.%d", version))
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	profiles, err := captureDiscoveryFeatureProfiles(ctx, binary, t.TempDir(), os.Environ(), plan, candidate.AsmFiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("source-required v1/v3 profiles = %d, want 2", len(profiles))
	}
	decisions, scopes, err := replayOrdinarySelectionForProfiles(plan, candidate.AsmFiles, profiles)
	if err != nil {
		t.Fatal(err)
	}
	plan.ProfileDecisions = decisions
	registration, err := captureDiscoveryCPPRegistration(runtime.GOROOT(), plan.GoVersion)
	if err != nil {
		t.Fatal(err)
	}
	cppSource, err := discoveryReplayCPPSource("vector_amd64.s", []byte("//go:build amd64.v3\n\nTEXT ·probe(SB),$0-0\nRET\n"))
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = &discoveryCPPInputs{
		Protocol: discoveryReplayCPPInputsProtocol, Module: plan.Module, Version: plan.Version,
		ModuleSum: plan.ModuleSum, ZipSHA256: plan.ZipSHA256, Registration: registration,
		Sources: map[string]discoveryCPPSource{"module/vector_amd64.s": cppSource},
		Units:   []discoveryCPPUnit{{File: "vector_amd64.s"}},
	}
	var selected discoveryFeatureProfile
	for _, profile := range profiles {
		if profile.Observed.Environment["GOAMD64"] == "v3" {
			selected = profile
		}
	}
	if len(scopes) != 1 || selected.ID == "" {
		t.Fatalf("source-required exact profile scopes = %#v", scopes)
	}
	inventory := &discoveryFeatureInventory{}
	refs, err := registerDiscoveryFeatureProfiles(inventory, profiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles,
		OrdinarySelectionPlan: plan, FeatureProfiles: refs, featureInventory: inventory,
		Translations:        1,
		BuildConfigurations: []discoveryBuildConfiguration{{ProfileID: selected.ID, AsmFiles: candidate.AsmFiles, Targets: []string{selected.Observed.Target}}},
	}
	// No compiler-consumption proof means this scope cannot be credited yet.
	if err := validateOrdinaryProfileResult(result, plan.Targets, plan.GoVersion); err == nil {
		t.Fatal("unconsumed JSON-only execution claim was accepted")
	}
	rootData, _, err := runDiscoveryMachineCommand(ctx, "", os.Environ(), binary, "env", "GOROOT")
	if err != nil {
		t.Fatal(err)
	}
	macros, err := captureDiscoveryAssemblerMacros(strings.TrimSpace(string(rootData)), selected.Observed, candidate.Module)
	if err != nil {
		t.Fatal(err)
	}
	cpp, consumed, err := replayDiscoveryOriginalCPP(plan.CPPInputs, plan.CPPInputs.Units[0], nil, macros.Defines)
	if err != nil {
		t.Fatal(err)
	}
	input := ordinaryProfileConsumerInput(plan, selected, candidate.Module, "", candidate.AsmFiles)
	expandedOperands, err := gotoolprofile.CPPExpandedOperands(input, "vector_amd64.s", cpp)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic object hashes exercise offline accounting, not LLVM/runtime
	// semantics; the separate actual compiler fixture covers real Go/LLVM objects.
	result.FeatureConsumption = []*gotoolprofile.SelectionProof{{
		SignatureSourceProtocol:      gotoolprofile.SignatureSourceProtocol,
		TestDependencySourceProtocol: gotoolprofile.TestDependencyProtocol,
		CPPSourceProtocol:            input.CPPSourceProtocol,
		CPPIncludeSearchMisses:       append([]gotoolprofile.CPPPackageSearchMiss(nil), input.CPPIncludeSearchMisses...),
		Protocol:                     gotoolprofile.ConsumerProtocol, ProfileID: selected.ID,
		Packages: []gotoolprofile.PackageProof{{PackagePath: candidate.Module, ModulePath: candidate.Module, ModuleVersion: candidate.Version,
			SourceModule: candidate.Module, SourceVersion: candidate.Version, SourceRole: "module",
			GoFiles: []string{"vector.go"}, CompiledGoFiles: []string{"vector.go"}, SFiles: candidate.AsmFiles, Macros: macros,
			SourceSHA256: map[string]string{"vector.go": input.Sources["vector.go"], "vector_amd64.s": input.Sources["vector_amd64.s"]}}},
		CPP: []gotoolprofile.CPPProof{{
			File: "vector_amd64.s", Emission: "assembly",
			ExpandedSearchMisses: expandedOperands,
			ExpandedSHA256:       discoveryFeatureBytesSHA256([]byte(cpp.Output)), TypedExpandedSHA256: strings.Repeat("2", 64),
			Inputs: consumed, Signatures: []gotoolprofile.SignatureSource{{
				Symbol: candidate.Module + ".probe", Role: "ordinary_decl", LayoutSHA256: strings.Repeat("5", 64),
			}},
		}},
		Outputs: []gotoolprofile.OutputProof{{File: "vector_amd64.s", Part: "vector_amd64.s.ll", IR: strings.Repeat("3", 64), Object: strings.Repeat("4", 64)}},
	}}
	if err := validateOrdinaryProfileResult(result, plan.Targets, plan.GoVersion); err != nil {
		t.Fatalf("complete frozen four-part compiler scope was rejected: %v", err)
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryCorpusAccounting(discoveryCorpusReport{SchemaVersion: 9, FeatureInventory: inventory, Results: []discoveryCorpusResult{result}}); err == nil {
		t.Fatal("schema 9 was allowed to relabel profile-aware compiler evidence")
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"missing source protocol":              func(result *discoveryCorpusResult) { result.OrdinarySelectionPlan.SignatureSourceProtocol = "" },
		"missing consumer protocol":            func(result *discoveryCorpusResult) { result.FeatureConsumption[0].SignatureSourceProtocol = "" },
		"missing dependency plan marker":       func(result *discoveryCorpusResult) { result.OrdinarySelectionPlan.TestDependencySourceProtocol = "" },
		"missing dependency consumer marker":   func(result *discoveryCorpusResult) { result.FeatureConsumption[0].TestDependencySourceProtocol = "" },
		"missing original CPP consumer marker": func(result *discoveryCorpusResult) { result.FeatureConsumption[0].CPPSourceProtocol = "" },
		"null expanded CPP operand set": func(result *discoveryCorpusResult) {
			result.FeatureConsumption[0].CPP[0].ExpandedSearchMisses = nil
		},
		"extra unconsumed expanded CPP operand": func(result *discoveryCorpusResult) {
			result.FeatureConsumption[0].CPP[0].ExpandedSearchMisses = []gotoolprofile.CPPPackageSearchMiss{{
				Protocol: gotoolprofile.CPPExpandedPackageSearchMissProtocol,
				Assembly: "vector_amd64.s", Include: "../../src/runtime/go_tls.h",
				PackageCandidate: "../../src/runtime/go_tls.h", ToolSource: "src/runtime/go_tls.h",
			}}
		},
		"missing consumed signatures":  func(result *discoveryCorpusResult) { result.FeatureConsumption[0].CPP[0].Signatures = nil },
		"old relabel missing profiles": func(result *discoveryCorpusResult) { result.FeatureProfiles = nil },
		"missing shared inventory":     func(result *discoveryCorpusResult) { result.featureInventory = nil },
		"omitted execution":            func(result *discoveryCorpusResult) { result.BuildConfigurations = nil },
		"wrong baseline ID":            func(result *discoveryCorpusResult) { result.BuildConfigurations[0].ProfileID = profiles[0].ID },
		"missing consumption":          func(result *discoveryCorpusResult) { result.FeatureConsumption = nil },
		"wrong consumed ID":            func(result *discoveryCorpusResult) { result.FeatureConsumption[0].ProfileID = profiles[0].ID },
		"wrong macro role": func(result *discoveryCorpusResult) {
			result.FeatureConsumption[0].Packages[0].Macros.PackageRole = "allow_asm_abi_path"
		},
		"wrong selected module version": func(result *discoveryCorpusResult) {
			result.FeatureConsumption[0].Packages[0].ModuleVersion = "v2.0.0"
		},
		"unpublished local source relabel": func(result *discoveryCorpusResult) {
			result.FeatureConsumption[0].Packages[0].SourceRole = "owned_local_replace"
		},
		"missing source decisions":   func(result *discoveryCorpusResult) { result.OrdinarySelectionPlan.ProfileDecisions = nil },
		"missing original ZIP hash":  func(result *discoveryCorpusResult) { result.OrdinarySelectionPlan.ZipSHA256 = "" },
		"missing exact ZIP h1":       func(result *discoveryCorpusResult) { result.OrdinarySelectionPlan.ModuleSum = "" },
		"missing original CPP graph": func(result *discoveryCorpusResult) { result.OrdinarySelectionPlan.CPPInputs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(canonical, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			mutate(&changed)
			if err := validateOrdinaryProfileResult(changed, plan.Targets, plan.GoVersion); err == nil {
				t.Fatal("legacy, omitted or contradictory four-part proof was accepted")
			}
		})
	}
	// The separate positive scope-map replay is the planner denominator, not
	// a compiler or runtime pass. Each ID and custom-tag dimension is retained.
	keys, err := ordinaryProfileConfigurationKeys(result.BuildConfigurations, scopes)
	if err != nil || len(keys) != 1 {
		t.Fatalf("actual four-part scope key was lost: %#v %v", keys, err)
	}
	for name, config := range map[string]discoveryBuildConfiguration{
		"missing profile": {AsmFiles: candidate.AsmFiles, Targets: []string{selected.Observed.Target}},
		"host baseline":   {ProfileID: profiles[0].ID, AsmFiles: candidate.AsmFiles, Targets: []string{selected.Observed.Target}},
		"custom CPU tag":  {ProfileID: selected.ID, BuildTags: []string{"amd64.v3"}, AsmFiles: candidate.AsmFiles, Targets: []string{selected.Observed.Target}},
		"target":          {ProfileID: selected.ID, AsmFiles: candidate.AsmFiles, Targets: []string{"linux/arm64"}},
		"file":            {ProfileID: selected.ID, AsmFiles: []string{"missing.s"}, Targets: []string{selected.Observed.Target}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ordinaryProfileConfigurationKeys([]discoveryBuildConfiguration{config}, scopes); err == nil {
				t.Fatal("missing/foreign scope dimension was accepted")
			}
		})
	}
}
