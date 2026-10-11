package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestAssemblyLedgerComparesValidatedHostIndependentProfiles(t *testing.T) {
	stored := fixtureSemanticProgress(t)
	current := cloneSemanticProgress(t, stored)
	// This is a portable protocol fixture, not a claim that a Linux tool was
	// executed. The ordinary producer has a separate actual-Go/LLVM fixture.
	moveSemanticFixtureTools(&current)
	if err := requireVerifiedAssemblyLedger(current); err != nil {
		t.Fatalf("the second host must independently retain complete evidence: %v", err)
	}
	before, _ := json.Marshal(current)
	if err := compareAssemblyLedgerProgress(stored, current); err != nil {
		t.Fatalf("same target/source/profile semantics with different host tools: %v", err)
	}
	after, _ := json.Marshal(current)
	if string(before) != string(after) {
		t.Fatal("comparison mutated the actual physical-tool evidence")
	}
}

func fixtureSemanticProgress(t *testing.T) discoveryProgress {
	t.Helper()
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	return progress
}

func cloneSemanticProgress(t *testing.T, source discoveryProgress) discoveryProgress {
	t.Helper()
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var copy discoveryProgress
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func moveSemanticFixtureTools(progress *discoveryProgress) {
	progress.Provenance.TranslatorSHA256 = strings.Repeat("e", 64)
	progress.Provenance.LLCBinarySHA256 = strings.Repeat("f", 64)
	replacements := make(map[string]string)
	inventory := newDiscoveryFeatureInventory()
	for id, observed := range progress.FeatureInventory.Observations {
		observed.DriverSHA256 = strings.Repeat("c", 64)
		observed.ToolDirectory = "pkg/tool/linux_amd64"
		observed.ToolRoutingSHA256 = strings.Repeat("d", 64)
		observed.EnvStderrSHA256 = strings.Repeat("e", 64)
		observed.EnvRecheckStderrSHA256 = strings.Repeat("f", 64)
		observed.ListStderrSHA256 = strings.Repeat("a", 64)
		for name := range observed.ToolBinarySHA256 {
			observed.ToolBinarySHA256[name] = strings.Repeat("b", 64)
			if strings.HasPrefix(observed.ToolBinaryOrigins[name], "goroot/") {
				observed.ToolBinaryOrigins[name] = "goroot/" + observed.ToolDirectory + "/" + name
			}
		}
		newID := discoveryFeatureProfileID(observed)
		replacements[id] = newID
		inventory.Observations[newID] = observed
	}
	progress.FeatureInventory = inventory
	rebindSemanticFixtureProfiles(progress, replacements)
	for index := range progress.Candidates {
		candidate := &progress.Candidates[index]
		if candidate.OrdinarySelectionPlan != nil {
			candidate.OrdinarySelectionPlan.ToolTags = []string{"amd64.v1"}
		}
		for _, proof := range candidate.FeatureConsumption {
			for index := range proof.Outputs {
				proof.Outputs[index].IR = strings.Repeat("e", 64)
				proof.Outputs[index].Object = strings.Repeat("f", 64)
			}
		}
	}
}

func rebindSemanticFixtureProfiles(progress *discoveryProgress, replacements map[string]string) {
	for index := range progress.Candidates {
		candidate := &progress.Candidates[index]
		for index := range candidate.FeatureProfiles {
			candidate.FeatureProfiles[index].ID = replacements[candidate.FeatureProfiles[index].ID]
		}
		for index := range candidate.BuildConfigurations {
			candidate.BuildConfigurations[index].ProfileID = replacements[candidate.BuildConfigurations[index].ProfileID]
		}
		if candidate.OrdinarySelectionPlan != nil {
			for index := range candidate.OrdinarySelectionPlan.ProfileDecisions {
				decision := &candidate.OrdinarySelectionPlan.ProfileDecisions[index]
				decision.ProfileID = replacements[decision.ProfileID]
			}
		}
		for _, proof := range candidate.FeatureConsumption {
			proof.ProfileID = replacements[proof.ProfileID]
			for index := range proof.Packages {
				proof.Packages[index].Macros.FeatureID = proof.ProfileID
			}
		}
		for index := range candidate.SourceNotApplicableItems {
			item := &candidate.SourceNotApplicableItems[index]
			item.ProfileID = replacements[item.ProfileID]
		}
		for index := range candidate.NotApplicableItems {
			item := &candidate.NotApplicableItems[index]
			item.ProfileID = replacements[item.ProfileID]
		}
	}
}

func TestAssemblyLedgerNativeHostTagsMustBeUnreferenced(t *testing.T) {
	stored := fixtureSemanticNativeProgress(t)
	current := cloneSemanticProgress(t, stored)
	current.Candidates[0].NativeLayoutPlan.ToolTags = []string{"amd64.v1"}
	for _, progress := range []discoveryProgress{stored, current} {
		if err := requireVerifiedAssemblyLedger(progress); err != nil {
			t.Fatalf("native original replay must independently succeed: %v", err)
		}
	}
	if err := compareAssemblyLedgerProgress(stored, current); err != nil {
		t.Fatalf("unreferenced host tags should not change native source/decision/witness semantics: %v", err)
	}

	// Even though amd64 makes this OR true on both hosts, the saved source
	// references arm64.v8.0. Different values cannot be silently projected out.
	for _, progress := range []*discoveryProgress{&stored, &current} {
		plan := progress.Candidates[0].NativeLayoutPlan
		header := "//go:build amd64 || arm64.v8.0\n\n"
		plan.Selections[0].Assembly.Header = header
		for index := range plan.SourceInventory {
			if plan.SourceInventory[index].File == plan.Selections[0].Assembly.File {
				plan.SourceInventory[index].Header = header
			}
		}
		if err := requireVerifiedAssemblyLedger(*progress); err != nil {
			t.Fatalf("referenced-tag fixture must retain valid original replay: %v", err)
		}
	}
	if err := compareAssemblyLedgerProgress(stored, current); err == nil {
		t.Fatal("ignored a referenced native feature merely because the OR selected the same file")
	}
}

func fixtureSemanticNativeProgress(t *testing.T) discoveryProgress {
	t.Helper()
	stored := fixtureSemanticProgress(t)
	candidate := &stored.Candidates[0]
	// Source-only capture from the exact cached official ZIP. No third-party
	// package was compiled/executed to create this fixture. ObjectHex is the
	// retained native-policy witness, not a newly executed object claim.
	data, err := os.ReadFile("testdata/native_semantic_source_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory []nativeLayoutSourceInput
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	skip := &discoveryNativeLayoutSkip{
		Module: "github.com/quasilyte/GopherJRE", Version: "v0.0.0-20250131090304-888098460476",
		AsmFile: "jruntime/call_amd64.s", Targets: []string{"linux/amd64"},
		SourceSHA256: "def9bd4b4d1faccabcd3b30722e7400b6f7bd0db415495c5ca4e9279dbc1afc0",
		Symbol:       "jcallScalar", ObjectHex: "488d0509000000488906", Reason: "native layout accounting fixture",
		EvidenceURLs: []string{"https://github.com/quasilyte/GopherJRE/blob/888098460476/jruntime/call_amd64.s"},
	}
	selection := nativeLayoutSourceSelection{}
	for _, source := range inventory {
		if source.File == skip.AsmFile {
			selection.Assembly = source
		} else {
			selection.GoFiles = append(selection.GoFiles, source)
		}
	}
	selection.Decisions = []nativeLayoutSelectionDecision{
		{Target: "linux/amd64", Kind: nativeLayoutSelected},
		{Target: "linux/arm64", Kind: nativeLayoutBuildConstraints,
			Reason: "Go filename or build constraints do not select an assembly/Go source pair"},
	}
	plan := &discoveryNativeLayoutPlan{
		GoVersion: "go1.27.1", Targets: stored.Targets, SourceInventory: inventory,
		Selections: []nativeLayoutSourceSelection{selection}, ToolTags: []string{"arm64.v8.0"},
		BuildConfigurations: []discoveryBuildConfiguration{{AsmFiles: []string{skip.AsmFile}, Targets: skip.Targets}},
	}
	for version := 1; version <= 27; version++ {
		plan.ReleaseTags = append(plan.ReleaseTags, fmt.Sprintf("go1.%d", version))
	}
	candidate.Module, candidate.Version = skip.Module, skip.Version
	candidate.DiscoveredAsmFiles = []string{skip.AsmFile}
	candidate.Status, candidate.Translations = discoveryStatusSkippedNativeLayout, 0
	candidate.NativeLayout, candidate.NativeLayoutPlan = skip, plan
	candidate.OrdinarySelectionPlan, candidate.BuildConfigurations = nil, nil
	candidate.ApplicableAsmFiles, candidate.FeatureProfiles, candidate.FeatureConsumption = nil, nil, nil
	stored.Passed--
	stored.SkippedNativeLayout++
	stored.Translations--
	return stored
}

func TestAssemblyLedgerSemanticComparisonRetainsValidatedInputs(t *testing.T) {
	stored := fixtureSemanticProgress(t)
	tests := []struct {
		name   string
		mutate func(*discoveryProgress)
	}{
		{"actual CPU profile", func(p *discoveryProgress) { changeSemanticFixtureCPU(t, p) }},
		{"source bytes", func(p *discoveryProgress) { changeSemanticFixtureSource(t, p) }},
		{"CPP registered source", func(p *discoveryProgress) {
			p.Candidates[0].OrdinarySelectionPlan.CPPInputs.Registration.ToolSourceSHA256["src/cmd/asm/internal/lex/input.go"] = strings.Repeat("9", 64)
		}},
		{"consumed CPP expansion", func(p *discoveryProgress) {
			before := p.Candidates[0].FeatureConsumption[0].CPP[0].ExpandedSHA256
			changeSemanticFixtureSource(t, p)
			if p.Candidates[0].FeatureConsumption[0].CPP[0].ExpandedSHA256 == before {
				t.Fatal("valid changed original did not change the consumed CPP expansion")
			}
		}},
		{"registered macro source", func(p *discoveryProgress) {
			p.Candidates[0].FeatureConsumption[0].Packages[0].Macros.ToolSourceSHA256["src/cmd/go/internal/work/gc.go"] = strings.Repeat("9", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := cloneSemanticProgress(t, stored)
			test.mutate(&current)
			if err := requireVerifiedAssemblyLedger(current); err != nil {
				t.Fatalf("different semantics must independently pass their own evidence replay: %v", err)
			}
			if err := compareAssemblyLedgerProgress(stored, current); err == nil {
				t.Fatal("accepted different target/source/profile/CPP semantics")
			}
		})
	}
}

func changeSemanticFixtureCPU(t *testing.T, progress *discoveryProgress) {
	t.Helper()
	replacements := make(map[string]string)
	inventory := newDiscoveryFeatureInventory()
	for oldID, observed := range progress.FeatureInventory.Observations {
		if observed.Target == "linux/amd64" {
			observed.Environment["GOAMD64"] = "v3"
			observed.MarkerSelection["amd64.v2"], observed.MarkerSelection["amd64.v3"] = true, true
			observed.ToolTags = uniqueSortedDiscoveryStrings(append(observed.ToolTags, "amd64.v2", "amd64.v3"))
			encoded, _ := json.Marshal(observed.MarkerSelection)
			observed.DriverSelectionSHA256 = discoveryFeatureBytesSHA256(encoded)
		}
		id := discoveryFeatureProfileID(observed)
		replacements[oldID], inventory.Observations[id] = id, observed
	}
	progress.FeatureInventory = inventory
	rebindSemanticFixtureProfiles(progress, replacements)
	for _, candidate := range progress.Candidates {
		for _, proof := range candidate.FeatureConsumption {
			observed := inventory.Observations[proof.ProfileID]
			defines, err := plan9asm.GoAssemblerDefinesForEnvironment(observed.Environment["GOOS"], observed.Environment["GOARCH"], observed.Environment)
			if err != nil {
				t.Fatal(err)
			}
			for _, pkg := range proof.Packages {
				pkg.Macros.Defines = defines
			}
		}
	}
}

func changeSemanticFixtureSource(t *testing.T, progress *discoveryProgress) {
	t.Helper()
	candidate := &progress.Candidates[0]
	file := candidate.DiscoveredAsmFiles[0]
	plan := candidate.OrdinarySelectionPlan
	source := plan.CPPInputs.Sources["module/"+file]
	if source.Original == nil {
		t.Fatal("portable semantic fixture lost its complete original")
	}
	changed := strings.Replace(*source.Original, "\nRET\n", "\nNOP\nRET\n", 1)
	if changed == *source.Original {
		t.Fatal("source mutation did not change the actual original")
	}
	source, err := discoveryReplayCPPSource(file, []byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs.Sources["module/"+file] = source
	changeSemanticFixtureSourceDigest(progress, source.SHA256)

	for _, proof := range candidate.FeatureConsumption {
		for index := range proof.CPP {
			cpp := &proof.CPP[index]
			if cpp.File != file {
				continue
			}
			for _, unit := range plan.CPPInputs.Units {
				if unit.File != file {
					continue
				}
				for _, pkg := range proof.Packages {
					if !containsTargetFeature(pkg.SFiles, file) {
						continue
					}
					observation, consumed, err := replayDiscoveryOriginalCPP(plan.CPPInputs, unit, nil, pkg.Macros.Defines)
					if err != nil {
						t.Fatal(err)
					}
					cpp.ExpandedSHA256 = discoveryFeatureBytesSHA256([]byte(observation.Output))
					cpp.Inputs = consumed
				}
			}
		}
	}
}

func changeSemanticFixtureSourceDigest(progress *discoveryProgress, digest string) {
	candidate := &progress.Candidates[0]
	file := candidate.DiscoveredAsmFiles[0]
	plan := candidate.OrdinarySelectionPlan
	for index := range plan.Sources {
		if plan.Sources[index].File == file {
			plan.Sources[index].SHA256 = digest
		}
	}
	for index := range plan.Directories {
		for entry := range plan.Directories[index].Entries {
			if plan.Directories[index].Entries[entry].Name == file {
				plan.Directories[index].Entries[entry].SHA256 = digest
			}
		}
	}
	source := plan.CPPInputs.Sources["module/"+file]
	source.SHA256 = digest
	plan.CPPInputs.Sources["module/"+file] = source
	for _, proof := range candidate.FeatureConsumption {
		for _, pkg := range proof.Packages {
			pkg.SourceSHA256[file] = digest
		}
		for _, cpp := range proof.CPP {
			cpp.Inputs["module/"+file] = digest
		}
	}
}

func TestAssemblyLedgerSemanticComparisonRejectsUnreplayedCPPInputs(t *testing.T) {
	stored := fixtureSemanticProgress(t)
	for _, test := range []struct {
		name   string
		mutate func(*discoveryProgress)
	}{
		{"source_digest_without_original", func(p *discoveryProgress) {
			changeSemanticFixtureSourceDigest(p, strings.Repeat("9", 64))
		}},
		{"consumed_output_without_source", func(p *discoveryProgress) {
			p.Candidates[0].FeatureConsumption[0].CPP[0].ExpandedSHA256 = strings.Repeat("9", 64)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := cloneSemanticProgress(t, stored)
			test.mutate(&current)
			if err := requireVerifiedAssemblyLedger(current); err == nil {
				t.Fatal("a digest-only mutation was accepted without full original CPP replay")
			}
			if err := compareAssemblyLedgerProgress(stored, current); err == nil {
				t.Fatal("semantic comparison repaired invalid CPP evidence")
			}
		})
	}
}

func TestAssemblyLedgerSemanticComparisonNeverRepairsIncompleteEvidence(t *testing.T) {
	stored := fixtureSemanticProgress(t)
	tests := []struct {
		name   string
		mutate func(*discoveryProgress)
	}{
		{"missing physical tool", func(p *discoveryProgress) {
			for _, observation := range p.FeatureInventory.Observations {
				observation.DriverSHA256 = ""
			}
		}},
		{"changed target", func(p *discoveryProgress) { p.Targets[0] = "darwin/amd64" }},
		{"provenance Go version", func(p *discoveryProgress) { p.Provenance.GoVersion = "go1.27.2" }},
		{"package role", func(p *discoveryProgress) {
			p.Candidates[0].FeatureConsumption[0].Packages[0].SourceRole = "owned_local_replace"
		}},
		{"CPP macros", func(p *discoveryProgress) { p.Candidates[0].FeatureConsumption[0].Packages[0].Macros.Defines = nil }},
		{"outcome", func(p *discoveryProgress) { p.Candidates[0].Status = discoveryStatusFailed }},
		{"translation count", func(p *discoveryProgress) { p.Candidates[0].Translations++ }},
		{"legacy progress", func(p *discoveryProgress) { p.SchemaVersion = 1 }},
		{"missing original source plan", func(p *discoveryProgress) { p.Candidates[0].OrdinarySelectionPlan = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := cloneSemanticProgress(t, stored)
			test.mutate(&current)
			if err := requireVerifiedAssemblyLedger(current); err == nil {
				t.Fatal("negative fixture unexpectedly has complete original evidence")
			}
			if err := compareAssemblyLedgerProgress(stored, current); err == nil {
				t.Fatal("comparison bypassed original full verification")
			}
		})
	}
}

func TestAssemblyLedgerSemanticComparisonKeepsTargetMatrix(t *testing.T) {
	stored := fixtureSemanticProgress(t)
	ledger, reports, source := writeDiscoveryReportFixtureWithTargets(t, []string{"darwin/amd64", "linux/arm64"})
	current, err := collectDiscoveryProgress(ledger, reports, []string{"darwin/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireVerifiedAssemblyLedger(current); err != nil {
		t.Fatalf("different target matrix must independently replay: %v", err)
	}
	if err := compareAssemblyLedgerProgress(stored, current); err == nil {
		t.Fatal("accepted a different independently verified target matrix")
	}
}

func TestAssemblyLedgerSemanticDiagnosticsKeepKindPositionsAndScope(t *testing.T) {
	stored := fixtureSemanticProgress(t)
	candidate := &stored.Candidates[0]
	for _, config := range candidate.BuildConfigurations {
		candidate.SourceNotApplicableItems = append(candidate.SourceNotApplicableItems, discoverySourceSkipSummary{
			ProfileID: config.ProfileID, BuildTags: config.BuildTags, AsmFiles: config.AsmFiles, Targets: config.Targets,
			Kind: discoverySourceNotApplicableGoBuild, Reason: discoverySourceSkipReason(discoverySourceNotApplicableGoBuild),
			Diagnostic: captureDiscoverySourceDiagnostic("/tmp/producer/source.go:3:14: undefined: missingDeclaration"),
		})
	}
	stored.Passed--
	stored.NotApplicable++
	stored.Translations -= candidate.Translations
	candidate.Status, candidate.Translations = discoveryStatusNotApplicable, 0
	candidate.BuildConfigurations, candidate.ApplicableAsmFiles, candidate.FeatureConsumption = nil, nil, nil
	candidate.NotApplicableReason = "source package rejected"
	if err := requireVerifiedAssemblyLedger(stored); err != nil {
		t.Fatalf("source diagnostic fixture must independently replay: %v", err)
	}
	current := cloneSemanticProgress(t, stored)
	current.Candidates[0].SourceNotApplicableItems[0].Diagnostic.SHA256 = strings.Repeat("a", 64)
	if err := compareAssemblyLedgerProgress(stored, current); err != nil {
		t.Fatalf("raw diagnostic text/path digest alone should not force a cross-host mismatch: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*discoverySourceSkipSummary)
	}{
		{"position", func(item *discoverySourceSkipSummary) { item.Diagnostic.Locations[0].Line++ }},
		{"kind", func(item *discoverySourceSkipSummary) {
			item.Kind = discoverySourceNotApplicableAsmDecl
			item.Reason = discoverySourceSkipReason(item.Kind)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := cloneSemanticProgress(t, stored)
			test.mutate(&current.Candidates[0].SourceNotApplicableItems[0])
			if err := requireVerifiedAssemblyLedger(current); err != nil {
				t.Fatalf("different diagnostic semantics must independently replay: %v", err)
			}
			if err := compareAssemblyLedgerProgress(stored, current); err == nil {
				t.Fatal("comparison erased concrete diagnostic kind/positions")
			}
		})
	}
}

func TestAssemblyLedgerSemanticNativeComparisonKeepsOriginalWitness(t *testing.T) {
	stored := fixtureSemanticNativeProgress(t)
	for _, test := range []struct {
		name   string
		mutate func(*discoveryCandidateProgress)
	}{
		{"native bytes", func(c *discoveryCandidateProgress) { c.NativeLayout.ObjectHex = "90" }},
		{"symbol", func(c *discoveryCandidateProgress) { c.NativeLayout.Symbol = "differentEntry" }},
		{"source", func(c *discoveryCandidateProgress) {
			c.NativeLayout.SourceSHA256 = strings.Repeat("9", 64)
			c.NativeLayoutPlan.Selections[0].Assembly.SHA256 = c.NativeLayout.SourceSHA256
			for index := range c.NativeLayoutPlan.SourceInventory {
				if c.NativeLayoutPlan.SourceInventory[index].File == c.NativeLayout.AsmFile {
					c.NativeLayoutPlan.SourceInventory[index].SHA256 = c.NativeLayout.SourceSHA256
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := cloneSemanticProgress(t, stored)
			test.mutate(&current.Candidates[0])
			if err := requireVerifiedAssemblyLedger(current); err != nil {
				t.Fatalf("changed valid native witness must independently replay: %v", err)
			}
			if err := compareAssemblyLedgerProgress(stored, current); err == nil {
				t.Fatal("semantic comparison discarded the native exception witness")
			}
		})
	}
}

func TestAssemblyLedgerCrossHostComparisonDoesNotRelaxSingleRunProvenance(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	name := filepath.Join(reports, "shard-0.json")
	report, err := readDiscoveryCorpusReport(name)
	if err != nil {
		t.Fatal(err)
	}
	report.Provenance.TranslatorSHA256 = strings.Repeat("9", 64)
	if err := writeDiscoveryCorpusReport(name, report); err != nil {
		t.Fatal(err)
	}
	if _, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2); err == nil {
		t.Fatal("accepted different physical translator identities within a single report run")
	}
}

func TestAssemblyLedgerSemanticLLVMContractUsesStrictlyVerifiedMajor(t *testing.T) {
	stored := fixtureSemanticProgress(t)
	current := cloneSemanticProgress(t, stored)
	stored.Provenance.LLVMVersion = "22.1.8"
	current.Provenance.LLVMVersion = "22.2.3"
	for _, progress := range []discoveryProgress{stored, current} {
		if err := requireVerifiedAssemblyLedger(progress); err != nil {
			t.Fatalf("each LLVM 22 patch must independently retain valid provenance: %v", err)
		}
	}
	if err := compareAssemblyLedgerProgress(stored, current); err != nil {
		t.Fatalf("independently verified LLVM 22 patch versions share the supported contract: %v", err)
	}
	if stored.Provenance.LLVMVersion != "22.1.8" || current.Provenance.LLVMVersion != "22.2.3" {
		t.Fatal("comparison overwrote the original exact LLVM version")
	}
	for _, version := range []string{"21.1.8", "23.1.0", "unknown", "LLVM version 22.1.8", "22.1.8-fallback", "22"} {
		t.Run(version, func(t *testing.T) {
			current := cloneSemanticProgress(t, stored)
			current.Provenance.LLVMVersion = version
			if err := compareAssemblyLedgerProgress(stored, current); err == nil {
				t.Fatal("unverified or unsupported LLVM version acquired a semantic comparison pass")
			}
		})
	}
}

func TestAssemblyLedgerSingleRunStillRequiresExactLLVMVersion(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	name := filepath.Join(reports, "shard-0.json")
	report, err := readDiscoveryCorpusReport(name)
	if err != nil {
		t.Fatal(err)
	}
	report.Provenance.LLVMVersion = "22.2.3"
	if err := writeDiscoveryCorpusReport(name, report); err != nil {
		t.Fatal(err)
	}
	if _, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2); err == nil {
		t.Fatal("accepted mixed exact LLVM versions within one frozen run")
	}
}
