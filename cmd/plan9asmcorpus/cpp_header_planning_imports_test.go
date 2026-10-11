package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestCPPHeaderPlanningImportsKeepEmptyRoleCanonical(t *testing.T) {
	role := &discoveryCPPHeaderPlanning{}
	imports, err := captureDiscoveryPlanningImports(role, &discoveryOrdinarySelectionPlan{},
		gotoolprofile.GeneratedHeaderProof{}, "example.invalid/header", t.TempDir())
	if err != nil || imports != nil || role.ImportedSources != nil {
		t.Fatalf("empty optional planning sources changed across JSON omission: %v %v %v", imports, role.ImportedSources, err)
	}
}

// This tests the property role boundary, not physical archive authentication or
// compiler acceptance. The full11 producer fixture supplies those separate gates.
func TestCPPHeaderPlanningImportsOwnCompleteQuerySources(t *testing.T) {
	const module = "example.invalid/header"
	const original = "package dependency\nconst Value = 7\n"
	digest := discoveryFeatureBytesSHA256([]byte(original))
	role := &discoveryCPPHeaderPlanning{
		ImportedSources: map[string]string{"dependency/value.go": original},
		Queries: []discoveryCPPHeaderPlanningQuery{{
			ImportedGoSHA256: map[string]string{"dependency/value.go": digest},
			Metadata: &gotoolprofile.MetadataProof{Headers: []gotoolprofile.GeneratedHeaderProof{{
				Imports: []gotoolprofile.ImportExport{{
					ModulePath: module, PackagePath: module + "/dependency",
					GoSHA256: map[string]string{"dependency/value.go": digest},
				}},
			}}},
		}},
	}
	got, err := replayDiscoveryPlanningImports(role, &role.Queries[0], module)
	if err != nil || len(got) != 1 || got["dependency/value.go"] != digest {
		t.Fatalf("complete exact query source role: %v %v", got, err)
	}
	got["dependency/value.go"] = "changed"
	if role.Queries[0].ImportedGoSHA256["dependency/value.go"] != digest {
		t.Fatal("consumer aliases the retained original query source map")
	}
	encoded, err := json.Marshal(role)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCPPHeaderPlanning){
		"role deletion":      func(role *discoveryCPPHeaderPlanning) { role.ImportedSources = nil },
		"reference deletion": func(role *discoveryCPPHeaderPlanning) { role.Queries[0].ImportedGoSHA256 = nil },
		"paired deletion": func(role *discoveryCPPHeaderPlanning) {
			role.ImportedSources, role.Queries[0].ImportedGoSHA256 = nil, nil
		},
		"changed bytes": func(role *discoveryCPPHeaderPlanning) {
			role.ImportedSources["dependency/value.go"] += "// changed\n"
		},
		"changed reference": func(role *discoveryCPPHeaderPlanning) {
			role.Queries[0].ImportedGoSHA256["dependency/value.go"] = strings.Repeat("1", 64)
		},
		"changed compiler selection": func(role *discoveryCPPHeaderPlanning) {
			role.Queries[0].Metadata.Headers[0].Imports[0].GoSHA256["dependency/value.go"] = strings.Repeat("1", 64)
		},
		"extra reference": func(role *discoveryCPPHeaderPlanning) {
			role.Queries[0].ImportedGoSHA256["other/value.go"] = digest
		},
		"query source reassignment": func(role *discoveryCPPHeaderPlanning) {
			role.Queries[0].ImportedGoSHA256 = map[string]string{"other/value.go": digest}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCPPHeaderPlanning
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if _, err := replayDiscoveryPlanningImports(&changed, &changed.Queries[0], module); err == nil {
				t.Fatal("missing/changed planning original source role was accepted")
			}
		})
	}
}
