package main

import (
	"encoding/json"

	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func checkDataOnlyQueryReaderMutants(t *testing.T, result discoveryCorpusResult, targets []string, inventory *discoveryFeatureInventory) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	type queryMutation struct {
		emission string
		apply    func(*gotoolprofile.CPPProof)
	}
	for name, mutation := range map[string]queryMutation{
		"query emission": {"data_only", func(cpp *gotoolprofile.CPPProof) { cpp.Emission = "assembly" }},
		"query native object": {"data_only", func(cpp *gotoolprofile.CPPProof) {
			cpp.DataOnlyAssembly.Native.ObjectSHA256 = strings.Repeat("a", 64)
		}},
		"query native listing": {"data_only", func(cpp *gotoolprofile.CPPProof) {
			cpp.DataOnlyAssembly.Native.ListingSHA256 = strings.Repeat("b", 64)
		}},
		"query native symbol size": {"data_only", func(cpp *gotoolprofile.CPPProof) { cpp.DataOnlyAssembly.Symbols[0].Size++ }},
		"query native symbol role": {"data_only", func(cpp *gotoolprofile.CPPProof) {
			cpp.DataOnlyAssembly.Symbols[0].Static = !cpp.DataOnlyAssembly.Symbols[0].Static
		}},
		"query native witness omitted": {"data_only", func(cpp *gotoolprofile.CPPProof) { cpp.DataOnlyAssembly = nil }},
		"query symbol-free native object": {"symbol_free", func(cpp *gotoolprofile.CPPProof) {
			cpp.EmptyAssembly.ObjectSHA256 = strings.Repeat("c", 64)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			registered := changed.OrdinarySelectionPlan.TestDeclarationQueries[0]
			mutateQuery := func(query *gotoolprofile.SignatureQueryProof) {
				for index := range query.Selection.CPP {
					if query.Selection.CPP[index].Emission == mutation.emission {
						mutation.apply(&query.Selection.CPP[index])
					}
				}
			}
			// Agreement between the producer and consumer preload alone is
			// insufficient. Keep both copies consistent so only their actual
			// native query/final identity boundary rejects changed evidence.
			mutateQuery(registered.Dependency.Query)
			for _, consumer := range changed.FeatureConsumption {
				if consumer.ProfileID == registered.ProfileID {
					mutateQuery(consumer.TestDependencies.Query)
				}
			}
			if err := validateOrdinaryProfileResult(changed, targets, changed.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatal("changed native query evidence was accepted by strict corpus reader")
			}
		})
	}
}
