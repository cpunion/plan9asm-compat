package main

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureNativeLayoutPlan(t *testing.T, skip *discoveryNativeLayoutSkip, files, targets []string, sources map[string]string) *discoveryNativeLayoutPlan {
	t.Helper()
	dir := t.TempDir()
	for _, file := range files {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(path.Dir(file))), 0755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, filepath.FromSlash(path.Join(path.Dir(file), "source.go"))), "package source\n")
		source := "TEXT ·probe(SB), $0-0\n\tRET\n"
		if contents, exists := sources[file]; exists {
			source = contents
		}
		writeTestFile(t, filepath.Join(dir, filepath.FromSlash(file)), source)
	}
	plan := &discoveryNativeLayoutPlan{}
	var sourceNA []discoverySourceNotApplicableItem
	if _, err := discoveryBuildConfigurationsWithEvidence(discoveryCandidate{AsmFiles: files}, dir, targets, &sourceNA, plan); err != nil {
		t.Fatal(err)
	}
	for _, selection := range plan.Selections {
		if selection.Assembly.File == skip.AsmFile {
			skip.SourceSHA256 = selection.Assembly.SHA256
		}
	}
	return plan
}

func fixtureNativeLayoutReviewResult(t *testing.T) discoveryCorpusResult {
	t.Helper()
	skip := discoveryNativeLayoutSkip{
		Module: "example.com/native", Version: "v1.0.0",
		AsmFile: "jit_amd64.s", Targets: []string{"linux/amd64", "windows/amd64"},
		Symbol: "jit", ObjectHex: "90", Reason: "byte-exact native entry",
		EvidenceURLs: []string{"https://example.com/source"},
	}
	files := []string{skip.AsmFile, "helper_amd64.s", "helper_arm64.s"}
	plan := fixtureNativeLayoutPlan(t, &skip, files, []string{"linux/amd64", "linux/arm64", "windows/amd64"}, nil)
	executed, active, err := filterNativeLayoutConfigurations(plan.BuildConfigurations, skip)
	if err != nil || !active {
		t.Fatalf("fixture filter = %v, %v", active, err)
	}
	result := discoveryCorpusResult{
		Module: skip.Module, Version: skip.Version, Status: discoveryStatusSkippedNativeLayout,
		DiscoveredAsmFiles: files, ApplicableAsmFiles: discoveryConfigurationAsmFiles(executed),
		BuildConfigurations: executed, Translations: 3, NativeLayout: &skip, NativeLayoutPlan: plan,
	}
	if err := validateNativeLayoutResult(result); err != nil {
		t.Fatal(err)
	}
	return result
}

func cloneNativeLayoutReviewResult(t *testing.T, result discoveryCorpusResult) discoveryCorpusResult {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var copy discoveryCorpusResult
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestNativeLayoutReviewRequiresCompletePreFilterProof(t *testing.T) {
	valid := fixtureNativeLayoutReviewResult(t)
	tests := []struct {
		name   string
		mutate func(*discoveryCorpusResult)
	}{
		{"missing_plan", func(r *discoveryCorpusResult) { r.NativeLayoutPlan = nil }},
		{"empty_plan", func(r *discoveryCorpusResult) { r.NativeLayoutPlan = &discoveryNativeLayoutPlan{} }},
		{"missing_inventory", func(r *discoveryCorpusResult) { r.NativeLayoutPlan.SourceInventory = nil }},
		{"duplicate_inventory", func(r *discoveryCorpusResult) {
			r.NativeLayoutPlan.SourceInventory = append(r.NativeLayoutPlan.SourceInventory, r.NativeLayoutPlan.SourceInventory[0])
		}},
		{"selection_constraint_input_changed", func(r *discoveryCorpusResult) {
			r.NativeLayoutPlan.Selections[1].GoFiles[0].Header = "//go:build ignore\n\npackage source\n"
		}},
		{"forged_no_go_exclusion", func(r *discoveryCorpusResult) {
			selection := &r.NativeLayoutPlan.Selections[1]
			selection.GoFiles, selection.Decisions = nil, nil
			selection.ExcludedKind = discoverySourceNotApplicableNoGoPackage
			selection.ExcludedReason = "forged no source"
		}},
		{"omitted_helper", func(r *discoveryCorpusResult) {
			r.BuildConfigurations = nil
			r.ApplicableAsmFiles = nil
			r.Translations = 0
		}},
		{"omitted_target", func(r *discoveryCorpusResult) {
			r.BuildConfigurations[0].Targets = r.BuildConfigurations[0].Targets[:1]
			r.Translations--
		}},
		{"duplicate_plan", func(r *discoveryCorpusResult) {
			r.NativeLayoutPlan.BuildConfigurations = append(r.NativeLayoutPlan.BuildConfigurations, r.NativeLayoutPlan.BuildConfigurations[0])
		}},
		{"reduced_plan", func(r *discoveryCorpusResult) {
			r.NativeLayoutPlan.BuildConfigurations = r.NativeLayoutPlan.BuildConfigurations[:1]
		}},
		{"missing_selection", func(r *discoveryCorpusResult) { r.NativeLayoutPlan.Selections = r.NativeLayoutPlan.Selections[:2] }},
		{"duplicate_selection", func(r *discoveryCorpusResult) {
			r.NativeLayoutPlan.Selections = append(r.NativeLayoutPlan.Selections, r.NativeLayoutPlan.Selections[0])
		}},
		{"missing_decision", func(r *discoveryCorpusResult) {
			r.NativeLayoutPlan.Selections[1].Decisions = r.NativeLayoutPlan.Selections[1].Decisions[:1]
		}},
		{"false_constraint_exclusion", func(r *discoveryCorpusResult) {
			for index, decision := range r.NativeLayoutPlan.Selections[1].Decisions {
				if decision.Kind == nativeLayoutSelected {
					r.NativeLayoutPlan.Selections[1].Decisions[index].Kind = nativeLayoutBuildConstraints
					r.NativeLayoutPlan.Selections[1].Decisions[index].Reason = "forged non-selection"
					break
				}
			}
		}},
		{"wrong_source_hash", func(r *discoveryCorpusResult) {
			r.NativeLayoutPlan.Selections[0].Assembly.SHA256 = strings.Repeat("f", 64)
		}},
		{"release_constraints_reduced", func(r *discoveryCorpusResult) {
			r.NativeLayoutPlan.ReleaseTags = r.NativeLayoutPlan.ReleaseTags[:1]
		}},
		{"duplicate_execution", func(r *discoveryCorpusResult) {
			r.BuildConfigurations = append(r.BuildConfigurations, r.BuildConfigurations[0])
			r.Translations += len(r.BuildConfigurations[0].AsmFiles) * len(r.BuildConfigurations[0].Targets)
		}},
		{"additional_configuration", func(r *discoveryCorpusResult) {
			r.BuildConfigurations = append(r.BuildConfigurations, discoveryBuildConfiguration{Targets: []string{"linux/arm64"}, AsmFiles: []string{"helper_amd64.s"}})
			r.Translations++
		}},
		{"unsupported_target_counts_without_evidence", func(r *discoveryCorpusResult) {
			r.NotApplicableTranslations, r.Translations = r.Translations, 0
		}},
		{"pinned_file_claimed_translated", func(r *discoveryCorpusResult) {
			r.BuildConfigurations[0].AsmFiles = append(r.BuildConfigurations[0].AsmFiles, r.NativeLayout.AsmFile)
			r.Translations += len(r.BuildConfigurations[0].Targets)
		}},
		{"unpinned_target", func(r *discoveryCorpusResult) { r.NativeLayout.Targets = []string{"linux/amd64"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := cloneNativeLayoutReviewResult(t, valid)
			test.mutate(&result)
			if err := validateNativeLayoutResult(result); err == nil {
				t.Fatal("accepted incomplete or falsified native-layout proof")
			}
		})
	}
}

func TestNativeLayoutReviewAccountsForSourceNotApplicableRemainder(t *testing.T) {
	valid := fixtureNativeLayoutReviewResult(t)
	for _, config := range valid.BuildConfigurations {
		valid.SourceNotApplicableItems = append(valid.SourceNotApplicableItems, discoverySourceNotApplicableItem{
			AsmFiles: config.AsmFiles, Targets: config.Targets, BuildTags: config.BuildTags,
			Kind: discoverySourceNotApplicableGoBuild, Reason: "decl.go:3:14: undefined: unavailableSourceDeclaration",
		})
	}
	valid.BuildConfigurations, valid.ApplicableAsmFiles, valid.Translations = nil, nil, 0
	if err := validateNativeLayoutResult(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*discoveryCorpusResult){
		func(r *discoveryCorpusResult) { r.SourceNotApplicableItems = nil },
		func(r *discoveryCorpusResult) { r.SourceNotApplicableItems[0].Targets = []string{"linux/arm64"} },
		func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems[0].AsmFiles = []string{r.NativeLayout.AsmFile}
		},
		func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems = append(r.SourceNotApplicableItems, r.SourceNotApplicableItems[0])
		},
		func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems[0].Reason = "checksum mismatch: SECURITY ERROR"
		},
		func(r *discoveryCorpusResult) { r.SourceNotApplicableItems[0].BuildTags = []string{"other_tag"} },
	} {
		result := cloneNativeLayoutReviewResult(t, valid)
		mutate(&result)
		if err := validateNativeLayoutResult(result); err == nil {
			t.Fatal("accepted missing or incorrectly scoped source N/A")
		}
	}
}

func TestNativeLayoutReviewDataAndPreSelectionExclusions(t *testing.T) {
	dir := t.TempDir()
	files := []string{"jit_amd64.s", "data_amd64.s", "empty_amd64.s", "orphan/orphan_amd64.s", "testdata/fixture_amd64.s", "nested/nested_amd64.s"}
	files = append(files, "invalid.s")
	writeTestFile(t, filepath.Join(dir, "source.go"), "package source\n")
	writeTestFile(t, filepath.Join(dir, files[0]), "TEXT ·jit(SB), $0-0\nRET\n")
	writeTestFile(t, filepath.Join(dir, files[1]), "DATA ·words+0(SB)/8, $1\nGLOBL ·words(SB), $8\n")
	if err := runCapturedCommand(context.Background(), dir, replaceEnv(os.Environ(), map[string]string{
		"GOOS": "linux", "GOARCH": "amd64", "GOTOOLCHAIN": "local", "GOWORK": "off",
	}), "go", "tool", "asm", "-o", filepath.Join(t.TempDir(), "data.o"), filepath.Join(dir, files[1])); err != nil {
		t.Fatalf("data-only source must be accepted by the real Go assembler: %v", err)
	}
	writeTestFile(t, filepath.Join(dir, files[2]), "// no object symbols\n")
	for _, file := range files[3:] {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(path.Dir(file))), 0755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, filepath.FromSlash(file)), "TEXT ·other(SB), $0-0\nRET\n")
	}
	writeTestFile(t, filepath.Join(dir, "nested", "go.mod"), "module example.com/nested\n")
	writeTestFile(t, filepath.Join(dir, "invalid.s"), "TEXT ·invalid(SB), $0-0\nNOT_A_GO_INSTRUCTION\n")
	plan := &discoveryNativeLayoutPlan{}
	var sourceNA []discoverySourceNotApplicableItem
	configs, err := discoveryBuildConfigurationsWithEvidence(discoveryCandidate{AsmFiles: files}, dir,
		[]string{"linux/amd64", "linux/arm64"}, &sourceNA, plan)
	if err != nil {
		t.Fatal(err)
	}
	skip := discoveryNativeLayoutSkip{
		Module: "example.com/data", Version: "v1.0.0", AsmFile: files[0], Targets: []string{"linux/amd64"},
		SourceSHA256: plan.Selections[0].Assembly.SHA256, Symbol: "jit", ObjectHex: "90", Reason: "native continuation",
	}
	executed, _, err := filterNativeLayoutConfigurations(configs, skip)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: skip.Module, Version: skip.Version, NativeLayout: &skip, NativeLayoutPlan: plan,
		DiscoveredAsmFiles: files, ApplicableAsmFiles: []string{files[1]}, BuildConfigurations: executed,
		Translations: 1, SourceNotApplicableItems: sourceNA,
	}
	if err := validateNativeLayoutResult(result); err != nil {
		t.Fatal(err)
	}
	if len(result.BuildConfigurations) != 1 || !equalDiscoveryStrings(result.BuildConfigurations[0].AsmFiles, []string{files[1]}) {
		t.Fatal("data-only object disappeared from the required compiled remainder")
	}
	result.SourceNotApplicableItems = nil
	if err := validateNativeLayoutResult(result); err == nil {
		t.Fatal("accepted no-symbol/no-Go-package exclusions without source N/A")
	}
}

func TestNativeLayoutReviewReplaysCustomAndWideConstraints(t *testing.T) {
	for _, tags := range []string{"feature", "a00 && a01 && a02 && a03 && a04 && a05 && a06 && a07 && a08 && a09 && a10 && a11 && a12 && a13 && a14 && a15 && a16"} {
		t.Run(tags, func(t *testing.T) {
			skip := discoveryNativeLayoutSkip{Module: "example.com/tags", Version: "v1.0.0", AsmFile: "jit_amd64.s",
				Targets: []string{"linux/amd64"}, Symbol: "jit", ObjectHex: "90", Reason: "native continuation"}
			files := []string{skip.AsmFile, "helper_amd64.s"}
			plan := fixtureNativeLayoutPlan(t, &skip, files, []string{"linux/amd64", "linux/arm64"}, map[string]string{
				"helper_amd64.s": "//go:build " + tags + "\n\nTEXT ·helper(SB), $0-0\nRET\n",
			})
			executed, _, err := filterNativeLayoutConfigurations(plan.BuildConfigurations, skip)
			if err != nil {
				t.Fatal(err)
			}
			result := discoveryCorpusResult{Module: skip.Module, Version: skip.Version, NativeLayout: &skip, NativeLayoutPlan: plan,
				DiscoveredAsmFiles: files, ApplicableAsmFiles: []string{files[1]}, BuildConfigurations: executed, Translations: 1}
			if err := validateNativeLayoutResult(result); err != nil {
				t.Fatal(err)
			}
			result.BuildConfigurations[0].BuildTags = nil
			if err := validateNativeLayoutResult(result); err == nil {
				t.Fatal("accepted execution without the selected source's required tags")
			}
		})
	}
}

func TestNativeLayoutReviewSourceGoVersionBindsProvenance(t *testing.T) {
	result := fixtureNativeLayoutReviewResult(t)
	report := discoveryCorpusReport{Targets: result.NativeLayoutPlan.Targets, Selected: 1,
		SkippedNativeLayout: 1, Translations: result.Translations, Results: []discoveryCorpusResult{result}}
	report.Provenance.GoVersion = result.NativeLayoutPlan.GoVersion + "-different"
	if err := validateDiscoveryCorpusAccounting(report); err == nil {
		t.Fatal("accepted source-selection proof from a different Go patch")
	}
}

func TestNativeLayoutReviewRejectsSchemaSevenReports(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	name := filepath.Join(reports, "shard-0.json")
	report, err := readDiscoveryCorpusReport(name)
	if err != nil {
		t.Fatal(err)
	}
	report.SchemaVersion = 7
	if err := writeDiscoveryCorpusReport(name, report); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source); err == nil || !strings.Contains(err.Error(), "schema 7") {
		t.Fatalf("schema-7 report upgrade should fail, got %v", err)
	}
}

func TestNativeLayoutReviewRejectsCoordinatedMatrixReduction(t *testing.T) {
	result := fixtureNativeLayoutReviewResult(t)
	result.NativeLayoutPlan.Targets = []string{"linux/amd64", "windows/amd64"}
	for i := range result.NativeLayoutPlan.Selections {
		selection := &result.NativeLayoutPlan.Selections[i]
		var decisions []nativeLayoutSelectionDecision
		for _, decision := range selection.Decisions {
			if decision.Target != "linux/arm64" {
				decisions = append(decisions, decision)
			}
		}
		selection.Decisions = decisions
	}
	var plan, executed []discoveryBuildConfiguration
	for _, config := range result.NativeLayoutPlan.BuildConfigurations {
		if !containsDiscoveryString(config.Targets, "linux/arm64") {
			plan = append(plan, config)
		}
	}
	for _, config := range result.BuildConfigurations {
		if !containsDiscoveryString(config.Targets, "linux/arm64") {
			executed = append(executed, config)
		}
	}
	result.NativeLayoutPlan.BuildConfigurations, result.BuildConfigurations = plan, executed
	result.Translations = 2
	result.ApplicableAsmFiles = discoveryConfigurationAsmFiles(executed)
	if err := validateNativeLayoutResult(result); err != nil {
		t.Fatalf("reduced proof is internally consistent; matrix gate must catch it: %v", err)
	}
	report := discoveryCorpusReport{
		Targets: []string{"linux/amd64", "linux/arm64", "windows/amd64"}, Selected: 1,
		SkippedNativeLayout: 1, Translations: 2, Results: []discoveryCorpusResult{result},
	}
	if err := validateDiscoveryCorpusAccounting(report); err == nil {
		t.Fatal("accepted native-layout plan with a deleted report-matrix target")
	}
}

func TestNativeLayoutReviewRejectsOmittedRemainder(t *testing.T) {
	skip := discoveryNativeLayoutSkip{
		Module: "example.com/native", Version: "v1.0.0",
		AsmFile: "jit_amd64.s", Targets: []string{"linux/amd64"},
		SourceSHA256: strings.Repeat("a", 64), Symbol: "jit", ObjectHex: "90",
		Reason: "byte-exact native entry", EvidenceURLs: []string{"https://example.com/source"},
	}
	result := discoveryCorpusResult{
		Module: skip.Module, Version: skip.Version,
		Status:             discoveryStatusSkippedNativeLayout,
		DiscoveredAsmFiles: []string{skip.AsmFile, "helper_amd64.s"},
		NativeLayout:       &skip,
	}
	if err := validateNativeLayoutResult(result); err == nil {
		t.Fatal("native-layout skip accepted an omitted remaining assembly file without compilation or source N/A evidence")
	}
}
