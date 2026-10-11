package main

import (
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func mutateZeroAssemblyDependencies(result *discoveryCorpusResult, mutate func(*gotoolprofile.TestDependencyProof)) {
	for index := range result.OrdinarySelectionPlan.TestDeclarationQueries {
		mutate(result.OrdinarySelectionPlan.TestDeclarationQueries[index].Dependency)
	}
	for _, proof := range result.FeatureConsumption {
		mutate(proof.TestDependencies)
	}
}
