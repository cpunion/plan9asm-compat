package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestGeneratedHeaderSemanticComparisonRetainsCompleteOriginAndDefinitions(t *testing.T) {
	stored := fixtureSemanticGeneratedProgress(t)
	current := cloneSemanticProgress(t, stored)
	moveSemanticFixtureTools(&current)
	for index := range current.Candidates {
		candidate := &current.Candidates[index]
		if candidate.OrdinarySelectionPlan == nil {
			continue
		}
		for index := range candidate.OrdinarySelectionPlan.GeneratedHeaders {
			query := &candidate.OrdinarySelectionPlan.GeneratedHeaders[index]
			original := stored.FeatureInventory.Observations[query.ProfileID]
			matches := 0
			for _, reference := range candidate.FeatureProfiles {
				observed := current.FeatureInventory.Observations[reference.ID]
				if original != nil && observed != nil && original.Target == observed.Target &&
					reflect.DeepEqual(original.Environment, observed.Environment) &&
					reflect.DeepEqual(original.ToolTags, observed.ToolTags) {
					query.ProfileID = reference.ID
					matches++
				}
			}
			if matches != 1 {
				t.Fatal("generated query lost its exact original CPU profile during host rebinding")
			}
			rebindGeneratedSemanticFixture(query.Metadata, query.ProfileID, current.FeatureInventory)
		}
		for _, proof := range candidate.FeatureConsumption {
			rebindGeneratedSemanticFixture(proof.GeneratedHeaders, proof.ProfileID, current.FeatureInventory)
		}
	}
	for _, progress := range []discoveryProgress{stored, current} {
		if err := requireVerifiedAssemblyLedger(progress); err != nil {
			t.Fatalf("both original snapshots must independently authenticate complete metadata: %v", err)
		}
	}
	if err := compareAssemblyLedgerProgress(stored, current); err != nil {
		t.Fatalf("physical compiler/header/object/export bytes must not break validated semantic comparison: %v", err)
	}
	for _, side := range []string{"producer", "consumer"} {
		for _, field := range []string{"export", "compile", "missing header", "missing object", "ImportMap", "value", "presence"} {
			t.Run(side+"/"+field, func(t *testing.T) {
				altered := cloneSemanticProgress(t, stored)
				for index := range altered.Candidates {
					candidate := &altered.Candidates[index]
					if candidate.OrdinarySelectionPlan == nil || len(candidate.OrdinarySelectionPlan.GeneratedHeaders) == 0 {
						continue
					}
					metadata := candidate.OrdinarySelectionPlan.GeneratedHeaders[0].Metadata
					if side == "consumer" {
						metadata = candidate.FeatureConsumption[0].GeneratedHeaders
					}
					header := &metadata.Headers[0]
					switch field {
					case "export":
						header.Imports[0].ExportSHA256 = strings.Repeat("2", 64)
					case "compile":
						header.CompileToolSHA256 = strings.Repeat("2", 64)
					case "missing header":
						header.HeaderSHA256 = ""
					case "missing object":
						header.ObjectSHA256 = ""
					case "ImportMap":
						header.ImportMap["fmt"] = "errors"
					default:
						mutateGeneratedSemanticMeaning(metadata, field)
					}
					break
				}
				if err := requireVerifiedAssemblyLedger(altered); err == nil {
					t.Fatal("one-sided tool/import/full-header alteration passed original-snapshot authentication")
				}
				if err := compareAssemblyLedgerProgress(stored, altered); err == nil {
					t.Fatal("cross-host projection bypassed the altered original's strict validation")
				}
			})
		}
	}
	for _, field := range []string{"value", "presence", "import source", "language", "import mapping"} {
		t.Run(field, func(t *testing.T) {
			altered := cloneSemanticProgress(t, current)
			for index := range altered.Candidates {
				candidate := &altered.Candidates[index]
				if candidate.OrdinarySelectionPlan == nil || len(candidate.OrdinarySelectionPlan.GeneratedHeaders) == 0 {
					continue
				}
				for queryIndex := range candidate.OrdinarySelectionPlan.GeneratedHeaders {
					mutateGeneratedSemanticMeaning(candidate.OrdinarySelectionPlan.GeneratedHeaders[queryIndex].Metadata, field)
				}
				for _, proof := range candidate.FeatureConsumption {
					mutateGeneratedSemanticMeaning(proof.GeneratedHeaders, field)
					canonical, err := gotoolprofile.CanonicalGeneratedHeader(proof.GeneratedHeaders.Headers[0].Definitions)
					if err != nil {
						t.Fatal(err)
					}
					proof.CPP[0].Inputs["generated/"+candidate.Module+"/go_asm.h"] = discoveryFeatureBytesSHA256(canonical)
				}
			}
			if err := requireVerifiedAssemblyLedger(altered); err != nil {
				t.Fatalf("self-consistent alternate semantic fixture should validate locally: %v", err)
			}
			if err := compareAssemblyLedgerProgress(stored, altered); err == nil {
				t.Fatal("cross-host comparison discarded full definition presence/value or dependency source identity")
			}
		})
	}
}

// This portable protocol fixture is deliberately synthetic, not Go/LLVM
// execution evidence. Actual producer/consumer compilation has separate tests.
func fixtureSemanticGeneratedProgress(t *testing.T) discoveryProgress {
	t.Helper()
	progress := fixtureSemanticProgress(t)
	for index, candidate := range progress.Candidates {
		if candidate.Status != discoveryStatusPassed || candidate.OrdinarySelectionPlan == nil {
			continue
		}
		const assembly = "#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-0\nRET\n"
		scanned := discoveryCandidate{Module: candidate.Module, Version: candidate.Version, AsmFiles: []string{"probe.s"}}
		plan := fixtureOrdinarySelectionForCandidate(t, scanned, progress.Targets, map[string]string{
			"go.mod":  "module " + candidate.Module + "\n\ngo 1.20\n",
			"decl.go": "package fixture\nimport \"fmt\"\nvar _ = fmt.Sprintf\nconst Answer = 7\nfunc Probe()\n",
			"probe.s": assembly,
		})
		result := discoveryCorpusResult{
			Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
			DiscoveredAsmFiles: scanned.AsmFiles, ApplicableAsmFiles: scanned.AsmFiles,
			Translations: len(progress.Targets), OrdinarySelectionPlan: plan,
			BuildConfigurations: []discoveryBuildConfiguration{{AsmFiles: scanned.AsmFiles, Targets: progress.Targets}},
		}
		definitions := map[string]string{"const_Answer": "7"}
		fixtureProfileEvidenceWithGeneratedHeaders(t, &result, progress.FeatureInventory,
			map[string]*gotoolprofile.GeneratedHeaderProof{
				"probe.s": {PackagePath: candidate.Module, Definitions: definitions},
			})
		for _, proof := range result.FeatureConsumption {
			observed := progress.FeatureInventory.Observations[proof.ProfileID]
			metadata := &gotoolprofile.MetadataProof{
				Protocol: gotoolprofile.MetadataProtocol, ProfileID: proof.ProfileID, Packages: proof.Packages,
				Headers: []gotoolprofile.GeneratedHeaderProof{{
					Protocol: gotoolprofile.GeneratedHeaderProtocol, PackagePath: candidate.Module,
					ProfileID: proof.ProfileID, Target: observed.Target, GoVersion: observed.GoVersion, LanguageVersion: "go1.20",
					CompileToolSHA256: observed.ToolBinarySHA256["compile"], HeaderSHA256: strings.Repeat("a", 64), ObjectSHA256: strings.Repeat("b", 64),
					Definitions: definitions, DefinitionsSHA256: gotoolprofile.HeaderDefinitionSHA256(definitions),
					CompiledGoSHA256: map[string]string{"decl.go": proof.Packages[0].SourceSHA256["decl.go"]},
					ImportMap:        map[string]string{"fmt": "fmt"}, Imports: []gotoolprofile.ImportExport{{
						ImportPath: "fmt", PackagePath: "fmt", SourceRole: "stdlib", ExportSHA256: strings.Repeat("c", 64),
						GoSHA256: map[string]string{"fmt/print.go": strings.Repeat("d", 64)},
					}},
				}},
			}
			metadata.Dependencies = fixtureSemanticGeneratedDependencies(plan, proof.Packages[0], observed.GoVersion)
			canonical, err := gotoolprofile.CanonicalGeneratedHeader(definitions)
			if err != nil {
				t.Fatal(err)
			}
			proof.GeneratedHeaders = metadata
			if proof.CPP[0].Inputs["generated/"+candidate.Module+"/go_asm.h"] != discoveryFeatureBytesSHA256(canonical) {
				t.Fatal("generated accounting header differs from the original CPP replay")
			}
			// The producer and independent consumer do not share mutable maps.
			data, _ := json.Marshal(metadata)
			var original gotoolprofile.MetadataProof
			if err := json.Unmarshal(data, &original); err != nil {
				t.Fatal(err)
			}
			plan.GeneratedHeaders = append(plan.GeneratedHeaders, discoveryGeneratedHeaderQuery{
				Target: observed.Target, ProfileID: proof.ProfileID, AsmFiles: scanned.AsmFiles, Metadata: &original,
			})
		}
		progress.Translations += result.Translations - candidate.Translations
		progress.Candidates[index] = discoveryCandidateProgress{
			Module: result.Module, Version: result.Version, Status: result.Status, Translations: result.Translations,
			DiscoveredAsmFiles: result.DiscoveredAsmFiles, ApplicableAsmFiles: result.ApplicableAsmFiles,
			BuildConfigurations: result.BuildConfigurations, OrdinarySelectionPlan: plan,
			FeatureProfiles: result.FeatureProfiles, FeatureConsumption: result.FeatureConsumption,
		}
		if err := requireVerifiedAssemblyLedger(progress); err != nil {
			t.Fatalf("portable full generated metadata fixture: %v", err)
		}
		return progress
	}
	t.Fatal("no ordinary pass to bind the portable metadata fixture")
	return progress
}

func rebindGeneratedSemanticFixture(metadata *gotoolprofile.MetadataProof, id string, inventory *discoveryFeatureInventory) {
	if metadata == nil {
		return
	}
	metadata.ProfileID = id
	for index := range metadata.Packages {
		metadata.Packages[index].Macros.FeatureID = id
	}
	for index := range metadata.Headers {
		header := &metadata.Headers[index]
		header.ProfileID, header.CompileToolSHA256 = id, inventory.Observations[id].ToolBinarySHA256["compile"]
		header.HeaderSHA256, header.ObjectSHA256 = strings.Repeat("e", 64), strings.Repeat("f", 64)
		for index := range header.Imports {
			header.Imports[index].ExportSHA256 = strings.Repeat("a", 64)
		}
	}
	for index := range metadata.Dependencies.ExternalPackages {
		metadata.Dependencies.ExternalPackages[index].ExportSHA256 = strings.Repeat("a", 64)
	}
}

func mutateGeneratedSemanticMeaning(metadata *gotoolprofile.MetadataProof, field string) {
	for index := range metadata.Headers {
		header := &metadata.Headers[index]
		switch field {
		case "value":
			header.Definitions["const_Answer"] = "9"
		case "presence":
			header.Definitions["const_Additional"] = "1"
		case "import source":
			header.Imports[0].GoSHA256["fmt/print.go"] = strings.Repeat("1", 64)
			metadata.Dependencies.ExternalPackages[0].Package.SourceSHA256["fmt/print.go"] = strings.Repeat("1", 64)
			metadata.Dependencies.SourceModules[0].Sources["fmt/print.go"] = strings.Repeat("1", 64)
			metadata.Dependencies.SourceModules[0].Directories["fmt"][0].SHA256 = strings.Repeat("1", 64)
		case "language":
			header.LanguageVersion = "go1.21"
		case "import mapping":
			header.ImportMap = map[string]string{"errors": "errors"}
			header.Imports[0].ImportPath, header.Imports[0].PackagePath = "errors", "errors"
			header.Imports[0].GoSHA256 = map[string]string{"errors/errors.go": strings.Repeat("d", 64)}
			// Preserve a complete internally valid alternate import/source graph;
			// cross-snapshot comparison must still reject its changed meaning.
			closure := metadata.Dependencies
			closure.Packages[0].ImportMap = header.ImportMap
			closure.Candidate.Headers["decl.go"] = strings.Replace(closure.Candidate.Headers["decl.go"], `"fmt"`, `"errors"`, 1)
			dep := &closure.ExternalPackages[0]
			dep.VariantID, dep.Package.PackagePath = "errors", "errors"
			dep.Package.GoFiles, dep.Package.CompiledGoFiles = []string{"errors/errors.go"}, []string{"errors/errors.go"}
			dep.Package.SourceSHA256 = header.Imports[0].GoSHA256
			dep.Embed.Directives = map[string]string{"errors/errors.go": ""}
			module := &closure.SourceModules[0]
			module.Sources = dep.Package.SourceSHA256
			module.Headers = map[string]string{"errors/errors.go": "package errors\n"}
			module.Directories = map[string][]gotoolprofile.TestSourceEntry{
				".": {{Name: "errors", Kind: "directory"}}, "errors": {{Name: "errors.go", Kind: "file", SHA256: strings.Repeat("d", 64)}},
			}
		}
		header.DefinitionsSHA256 = gotoolprofile.HeaderDefinitionSHA256(header.Definitions)
	}
}

func fixtureSemanticGeneratedDependencies(plan *discoveryOrdinarySelectionPlan, pkg gotoolprofile.PackageProof, goVersion string) *gotoolprofile.OrdinaryDependencyProof {
	inventory := gotoolprofile.SourceInventory{Sources: make(map[string]string), Headers: make(map[string]string), Directories: make(map[string][]gotoolprofile.TestSourceEntry)}
	for _, directory := range plan.Directories {
		inventory.Directories[directory.Directory] = []gotoolprofile.TestSourceEntry{}
		for _, entry := range directory.Entries {
			inventory.Directories[directory.Directory] = append(inventory.Directories[directory.Directory], gotoolprofile.TestSourceEntry{Name: entry.Name, Kind: entry.Kind, SHA256: entry.SHA256})
			if entry.Kind == "file" {
				inventory.Sources[strings.TrimPrefix(directory.Directory+"/"+entry.Name, "./")] = entry.SHA256
			}
		}
	}
	for _, source := range plan.Sources {
		if strings.HasSuffix(source.File, ".go") || strings.HasSuffix(source.File, ".s") {
			inventory.Headers[source.File] = source.Header
		}
	}
	pkg.Macros = nil
	root := gotoolprofile.SourcePackageProof{Package: pkg, VariantID: pkg.PackagePath, ImportMap: map[string]string{"fmt": "fmt"},
		Embed: &gotoolprofile.EmbedSelection{Protocol: gotoolprofile.TestEmbedProtocol, Directives: map[string]string{"decl.go": ""}, Files: map[string]string{}},
	}
	module := gotoolprofile.ModuleSourceSnapshot{Protocol: gotoolprofile.TestDependencyModuleProtocol, GoVersion: goVersion,
		Sources: map[string]string{"fmt/print.go": strings.Repeat("d", 64)}, Headers: map[string]string{"fmt/print.go": "package fmt\n"},
		Directories: map[string][]gotoolprofile.TestSourceEntry{".": {{Name: "fmt", Kind: "directory"}}, "fmt": {{Name: "print.go", Kind: "file", SHA256: strings.Repeat("d", 64)}}},
	}
	dep := gotoolprofile.SourcePackageProof{Package: gotoolprofile.PackageProof{PackagePath: "fmt", SourceRole: "stdlib", GoFiles: []string{"fmt/print.go"}, CompiledGoFiles: []string{"fmt/print.go"}, SourceSHA256: module.Sources},
		VariantID: "fmt", ImportMap: map[string]string{}, SourceRootID: module.ID(), ExportSHA256: strings.Repeat("c", 64),
		Embed: &gotoolprofile.EmbedSelection{Protocol: gotoolprofile.TestEmbedProtocol, Directives: map[string]string{"fmt/print.go": ""}, Files: map[string]string{}},
	}
	return &gotoolprofile.OrdinaryDependencyProof{Protocol: gotoolprofile.OrdinaryDependencyProtocol, Candidate: inventory,
		Packages: []gotoolprofile.SourcePackageProof{root}, ExternalPackages: []gotoolprofile.SourcePackageProof{dep}, SourceModules: []gotoolprofile.ModuleSourceSnapshot{module}}
}
