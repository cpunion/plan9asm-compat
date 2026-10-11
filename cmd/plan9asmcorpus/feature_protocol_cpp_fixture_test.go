package main

import (
	"encoding/json"
	"testing"
)

// These are portable accounting fixtures, not external-module object or
// runtime witnesses. Even synthetic accounting must preserve full CPP inputs.
func TestPortableAccountingFixtureRetainsCurrentOriginalCPP(t *testing.T) {
	candidate := discoveryCandidate{
		Module: "example.com/cpp-accounting", Version: "v1.0.0",
		AsmFiles: []string{"probe.s"},
	}
	result := fixtureOrdinaryPassedResult(t, candidate, []string{"linux/amd64", "linux/arm64"})
	plan := result.OrdinarySelectionPlan
	if plan.CPPSourceProtocol != discoveryReplayCPPInputsProtocol || plan.CPPInputs == nil ||
		plan.CPPInputs.Protocol != discoveryReplayCPPInputsProtocol {
		t.Fatal("fresh accounting fixture silently retained a historical CPP graph")
	}
	for file, source := range plan.CPPInputs.Sources {
		if source.Original == nil || discoveryFeatureBytesSHA256([]byte(*source.Original)) != source.SHA256 {
			t.Fatalf("fresh CPP fixture lost its complete original: %s", file)
		}
	}
	if err := validateOrdinaryProfileResult(result, plan.Targets, plan.GoVersion); err != nil {
		t.Fatalf("fresh original-source accounting failed: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name string
		edit func(*discoveryCorpusResult)
	}{
		{
			name: "paired_legacy_downgrade",
			edit: func(copy *discoveryCorpusResult) {
				copy.OrdinarySelectionPlan.CPPSourceProtocol = discoveryCPPInputsProtocol
				copy.OrdinarySelectionPlan.CPPInputs.Protocol = discoveryCPPInputsProtocol
			},
		},
		{
			name: "paired_source_graph_deletion",
			edit: func(copy *discoveryCorpusResult) {
				copy.OrdinarySelectionPlan.CPPSourceProtocol = ""
				copy.OrdinarySelectionPlan.CPPInputs = nil
			},
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = result.featureInventory
			mutation.edit(&changed)
			if err := validateOrdinaryProfileResult(changed, plan.Targets, plan.GoVersion); err == nil {
				t.Fatal("legacy or deleted original graph was accepted as a current fixture")
			}
		})
	}
}

func TestPortableAccountingGeneratedHeaderRetainsCurrentOriginalCPP(t *testing.T) {
	progress := fixtureSemanticGeneratedProgress(t)
	for _, candidate := range progress.Candidates {
		plan := candidate.OrdinarySelectionPlan
		if plan == nil || len(plan.GeneratedHeaders) == 0 {
			continue
		}
		if plan.CPPSourceProtocol != discoveryReplayCPPInputsProtocol ||
			plan.CPPInputs.Protocol != discoveryReplayCPPInputsProtocol {
			t.Fatal("generated-header fixture downgraded its original CPP graph")
		}
		for _, proof := range candidate.FeatureConsumption {
			if proof.GeneratedHeaders == nil || len(proof.GeneratedHeaders.Headers) != 1 || len(proof.Packages) != 1 {
				t.Fatal("generated-header fixture lost its independent package/header binding")
			}
			header := &proof.GeneratedHeaders.Headers[0]
			for _, cpp := range proof.CPP {
				var unit discoveryCPPUnit
				for _, registered := range plan.CPPInputs.Units {
					if registered.File == cpp.File {
						unit = registered
						break
					}
				}
				if len(unit.DeferredIncludes) != 1 {
					t.Fatal("generated-header fixture lost its exact original include edge")
				}
				if err := validateDiscoveryOriginalCPPConsumption(plan.CPPInputs, unit, header,
					proof.Packages[0].Macros.Defines, cpp); err != nil {
					t.Fatalf("generated header was not replayed with the complete original: %v", err)
				}
			}
		}
		for _, mutation := range []string{"downgrade", "delete_original", "delete_include"} {
			t.Run(mutation, func(t *testing.T) {
				changed := cloneSemanticProgress(t, progress)
				for index := range changed.Candidates {
					plan := changed.Candidates[index].OrdinarySelectionPlan
					if plan == nil || len(plan.GeneratedHeaders) == 0 {
						continue
					}
					switch mutation {
					case "downgrade":
						plan.CPPSourceProtocol = discoveryDeferredCPPInputsProtocol
						plan.CPPInputs.Protocol = discoveryDeferredCPPInputsProtocol
					case "delete_original":
						source := plan.CPPInputs.Sources["module/probe.s"]
						source.Original = nil
						plan.CPPInputs.Sources["module/probe.s"] = source
					case "delete_include":
						plan.CPPInputs.Units[0].DeferredIncludes = nil
					}
					break
				}
				if err := requireVerifiedAssemblyLedger(changed); err == nil {
					t.Fatal("generated-header accounting accepted incomplete original-source evidence")
				}
			})
		}
		return
	}
	t.Fatal("fixture contained no generated-header candidate")
}
