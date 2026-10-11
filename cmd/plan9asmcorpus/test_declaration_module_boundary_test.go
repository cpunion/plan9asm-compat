package main

import (
	"encoding/json"

	"reflect"

	"testing"
)

func assertTestModuleSemanticProjection(t *testing.T, result discoveryCorpusResult, inventory *discoveryFeatureInventory) {
	t.Helper()
	// This private comparison view is not a verified ledger. Its source comes
	// from the actual producer/consumer result already validated above. A real
	// cross-host comparison still requires two independently verified ledgers.
	physical := discoveryProgress{
		Provenance:       &discoveryCorpusProvenance{},
		FeatureInventory: inventory,
		Candidates: []discoveryCandidateProgress{{
			OrdinarySelectionPlan: result.OrdinarySelectionPlan,
			FeatureConsumption:    result.FeatureConsumption,
		}},
	}
	before, err := json.Marshal(physical)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := semanticAssemblyLedgerProgress(physical)
	if err != nil {
		t.Fatal(err)
	}
	for i, original := range result.FeatureConsumption[0].TestDependencies.ExternalPackages {
		projected := semantic.Candidates[0].FeatureConsumption[0].TestDependencies.ExternalPackages[i]
		if projected.ExportSHA256 != "" {
			t.Fatal("cross-host view kept physical dependency export bytes")
		}
		projected.ExportSHA256 = original.ExportSHA256
		if !reflect.DeepEqual(projected, original) {
			t.Fatal("cross-host view discarded dependency module/source/ImportMap/builtin semantics")
		}
	}
	original := result.FeatureConsumption[0].TestDependencies.SourceModules
	projected := semantic.Candidates[0].FeatureConsumption[0].TestDependencies.SourceModules
	if !reflect.DeepEqual(original, projected) {
		t.Fatal("cross-host view discarded original ZIP/mod/tool-source/member/header identity")
	}
	after, err := json.Marshal(physical)
	if err != nil || string(before) != string(after) {
		t.Fatal("semantic comparison modified the independently verified physical evidence")
	}
}
