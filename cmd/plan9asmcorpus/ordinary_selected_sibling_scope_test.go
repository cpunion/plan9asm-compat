package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrdinarySelectionIncludesGoSelectedNonemptyAssemblySibling(t *testing.T) {
	candidate := discoveryCandidate{
		Module: "example.invalid/selected-sibling", Version: "v1.0.0",
		AsmFiles: []string{"probe.s"},
	}
	sources := map[string]string{
		"go.mod":   "module example.invalid/selected-sibling\n\ngo 1.20\n",
		"probe.go": "package sibling\nfunc Probe()\n",
		"probe.s":  "TEXT ·Probe(SB),4,$0-0\nRET\n",
		"cpu.s":    "// This nonempty assembly placeholder is selected by Go.\n",
		"empty.s":  "",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env := append(os.Environ(),
		"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local",
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
		"GOCACHE="+filepath.Join(t.TempDir(), "build"),
	)
	output, _, err := runDiscoveryMachineCommand(ctx, download.Dir, env, "go", "list", "-json", ".")
	if err != nil {
		t.Fatal(err)
	}
	var selected struct {
		SFiles []string
	}
	if err := json.Unmarshal(output, &selected); err != nil {
		t.Fatal(err)
	}
	if !equalDiscoveryStrings(selected.SFiles, []string{"cpu.s", "empty.s", "probe.s"}) {
		t.Fatalf("actual Go selected unexpected assembly: %v", selected.SFiles)
	}

	plan, err := captureOrdinarySelectionPlan(candidate, download.Dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOrdinarySelectionZIP(plan, download.Zip, candidate.Module, candidate.Version, ""); err != nil {
		t.Fatal(err)
	}
	var selectedForConsumption []string
	for _, decision := range plan.Decisions {
		if decision.Kind == nativeLayoutSelected {
			selectedForConsumption = append(selectedForConsumption, decision.AsmFiles...)
		}
	}
	selectedForConsumption = uniqueSortedDiscoveryStrings(selectedForConsumption)
	if !equalDiscoveryStrings(selectedForConsumption, []string{"cpu.s", "probe.s"}) {
		t.Fatalf("nonempty actual Go-selected sibling omitted from the tested scope: got %v, want [cpu.s probe.s]; discovered inventory must remain %v",
			selectedForConsumption, candidate.AsmFiles)
	}
}

func TestOrdinaryAssemblyScopeRejectsUnboundAndLegacyClaims(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/scope", Version: "v1.0.0", AsmFiles: []string{"pkg/probe.s"}}
	download := fixtureProfileModuleDownload(t, candidate, map[string]string{
		"go.mod":       "module example.invalid/scope\n\ngo 1.20\n",
		"pkg/probe.go": "package scope\nfunc Probe()\n",
		"pkg/probe.s":  "TEXT ·Probe(SB),4,$0-0\nRET\n",
		"pkg/cpu.s":    "// original nonempty sibling\n",
		"pkg/empty.s":  "",
		"outside.s":    "// outside the inventoried package\n",
	})
	plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if !equalDiscoveryStrings(plan.TestedAsmFiles, []string{"pkg/cpu.s", "pkg/probe.s"}) {
		t.Fatal(plan.TestedAsmFiles)
	}
	if _, err := deriveOrdinaryAssemblyScope(plan, []string{"pkg/probe.s", "pkg/probe.s"}); err == nil {
		t.Fatal("duplicate discovered inventory was silently normalized")
	}
	for name, mutate := range map[string]func(*discoveryOrdinarySelectionPlan){
		"omitted sibling": func(plan *discoveryOrdinarySelectionPlan) { plan.TestedAsmFiles = candidate.AsmFiles },
		"invented sibling": func(plan *discoveryOrdinarySelectionPlan) {
			plan.TestedAsmFiles = append(plan.TestedAsmFiles, "pkg/unknown.s")
		},
		"duplicate tested sibling": func(plan *discoveryOrdinarySelectionPlan) {
			plan.TestedAsmFiles = append(plan.TestedAsmFiles, "pkg/probe.s")
		},
		"zero-byte scope inflation": func(plan *discoveryOrdinarySelectionPlan) {
			plan.TestedAsmFiles = uniqueSortedDiscoveryStrings(append(plan.TestedAsmFiles, "pkg/empty.s"))
		},
		"outside package": func(plan *discoveryOrdinarySelectionPlan) {
			plan.TestedAsmFiles = uniqueSortedDiscoveryStrings(append(plan.TestedAsmFiles, "outside.s"))
		},
		"missing source witness": func(plan *discoveryOrdinarySelectionPlan) {
			for index, source := range plan.Sources {
				if source.File == "pkg/cpu.s" {
					plan.Sources = append(plan.Sources[:index], plan.Sources[index+1:]...)
					return
				}
			}
		},
		"unknown full hash": func(plan *discoveryOrdinarySelectionPlan) {
			for index := range plan.Sources {
				if plan.Sources[index].File == "pkg/cpu.s" {
					plan.Sources[index].SHA256 = ""
				}
			}
		},
		"forged zero source hash": func(plan *discoveryOrdinarySelectionPlan) {
			for index := range plan.Sources {
				if plan.Sources[index].File == "pkg/cpu.s" {
					plan.Sources[index].SHA256 = discoveryFeatureBytesSHA256(nil)
				}
			}
		},
		"legacy scope relabel": func(plan *discoveryOrdinarySelectionPlan) { plan.Protocol = ordinarySelectionProtocol },
	} {
		t.Run(name, func(t *testing.T) {
			copy := cloneSelectedSiblingPlan(t, plan)
			mutate(copy)
			if _, err := ordinarySelectionTestedAssembly(copy, candidate.AsmFiles); err == nil {
				t.Fatal("accepted an unbound tested scope")
			}
		})
	}
	legacy := cloneSelectedSiblingPlan(t, plan)
	legacy.Protocol, legacy.TestedAsmFiles = ordinarySelectionProtocol, nil
	scope, err := ordinarySelectionTestedAssembly(legacy, candidate.AsmFiles)
	if err != nil || !equalDiscoveryStrings(scope, candidate.AsmFiles) {
		t.Fatalf("historical v1 scope was expanded or invalidated: %v %v", scope, err)
	}
}

func cloneSelectedSiblingPlan(t *testing.T, plan *discoveryOrdinarySelectionPlan) *discoveryOrdinarySelectionPlan {
	t.Helper()
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var copy discoveryOrdinarySelectionPlan
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return &copy
}

func TestOrdinaryAssemblyScopePreservesNestedAndIgnoredBoundaries(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/boundaries", Version: "v1.0.0",
		AsmFiles: []string{"_ignored/probe.s", "nested/probe.s", "pkg/probe.s"}}
	sources := map[string]string{"go.mod": "module example.invalid/boundaries\n", "nested/go.mod": "module example.invalid/nested\n"}
	for _, dir := range []string{"_ignored", "nested", "pkg"} {
		sources[dir+"/probe.go"] = "package fixture\nfunc Probe()\n"
		sources[dir+"/probe.s"] = "TEXT ·Probe(SB),4,$0-0\nRET\n"
		sources[dir+"/cpu.s"] = "// original same-directory sibling\n"
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	plan, err := captureOrdinarySelectionPlan(candidate, download.Dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	for _, decision := range plan.Decisions {
		for _, file := range decision.AsmFiles {
			switch {
			case strings.HasPrefix(file, "_ignored/"):
				if decision.Kind != nativeLayoutIgnoredDirectory {
					t.Fatalf("ignored sibling was selected: %#v", decision)
				}
			case strings.HasPrefix(file, "nested/"):
				if decision.Kind != nativeLayoutNestedModule {
					t.Fatalf("nested-module sibling crossed its boundary: %#v", decision)
				}
			case decision.Kind != nativeLayoutSelected:
				t.Fatalf("ordinary package sibling lost its selected scope: %#v", decision)
			}
		}
	}
}

func TestOrdinaryAssemblyScopeSharedCustomTags(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/tag-siblings", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
	download := fixtureProfileModuleDownload(t, candidate, map[string]string{
		"go.mod":    "module example.invalid/tag-siblings\n\ngo 1.20\n",
		"probe.go":  "package fixture\nfunc Probe()\nfunc Variant()\n",
		"probe.s":   "TEXT ·Probe(SB),4,$0-0\nRET\n",
		"variant.s": "//go:build custom\n\nTEXT ·Variant(SB),4,$0-0\nRET\n",
		"cpu.s":     "// shared nonempty placeholder\n",
	})
	plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/arm64"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := captureDiscoveryFeatureProfiles(ctx, binary, t.TempDir(), targetFeatureTestEnv(), plan, plan.TestedAsmFiles)
	if err != nil {
		t.Fatal(err)
	}
	_, scopes, err := replayOrdinarySelectionForProfiles(plan, plan.TestedAsmFiles, profiles)
	if err != nil {
		t.Fatal(err)
	}
	var actual []string
	for scope := range scopes {
		actual = append(actual, scope.File+"#"+scope.Tags)
	}
	want := []string{"cpu.s#", "cpu.s#custom", "probe.s#", "probe.s#custom", "variant.s#custom"}
	if !equalDiscoveryStrings(uniqueSortedDiscoveryStrings(actual), want) {
		t.Fatalf("new sibling did not close the whole package/custom-tag scope: %v, want %v", actual, want)
	}
}

func checkSelectedSiblingReportReaders(t *testing.T, candidate discoveryCandidate, result discoveryCorpusResult, targets []string, inventory *discoveryFeatureInventory) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := os.MkdirAll(filepath.Join(ledger, "records"), 0755); err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(discoveryRecord{Kind: "matched", Module: candidate.Module, Version: candidate.Version, AsmFiles: candidate.AsmFiles})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(ledger, "records", "00.jsonl"), string(record)+"\n")
	provenance := fixtureDiscoveryProvenance(t, ledger) // Reader identity fixture, not an external-library pass.
	report := discoveryCorpusReport{
		SchemaVersion: discoveryReportSchema, Provenance: provenance, Targets: targets, ShardCount: 1,
		CandidateTotal: 1, EligibleCandidates: 1, Selected: 1, Passed: 1, Translations: result.Translations,
		Results: []discoveryCorpusResult{result}, FeatureInventory: inventory,
	}
	reports := t.TempDir()
	filename := filepath.Join(reports, "shard-0.json")
	if err := writeDiscoveryCorpusReport(filename, report); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, targets, provenance.Source); err != nil {
		t.Fatal(err)
	}
	progress, err := collectDiscoveryProgress(ledger, reports, targets, provenance.Source, 1)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semantic := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semantic); err != nil {
		t.Fatal(err)
	}
	replayed, err := readAssemblyLedger(output, progress.LedgerSHA256, semantic)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed.Candidates) != 1 || !equalDiscoveryStrings(replayed.Candidates[0].DiscoveredAsmFiles, candidate.AsmFiles) ||
		!equalDiscoveryStrings(replayed.Candidates[0].OrdinarySelectionPlan.TestedAsmFiles, result.OrdinarySelectionPlan.TestedAsmFiles) {
		t.Fatal("report/progress/assembly-ledger replay changed the original inventory or tested scope")
	}
	report.Results[0].OrdinarySelectionPlan = cloneSelectedSiblingPlan(t, result.OrdinarySelectionPlan)
	report.Results[0].OrdinarySelectionPlan.TestedAsmFiles = candidate.AsmFiles
	if err := writeDiscoveryCorpusReport(filename, report); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, targets, provenance.Source); err == nil {
		t.Fatal("aggregate reader accepted an omitted original sibling")
	}
	if _, err := collectDiscoveryProgress(ledger, reports, targets, provenance.Source, 1); err == nil {
		t.Fatal("progress reader accepted an omitted original sibling")
	}
	replayed.Candidates[0].OrdinarySelectionPlan.TestedAsmFiles = candidate.AsmFiles
	if err := validateAssemblyLedgerProgress(replayed); err == nil {
		t.Fatal("assembly-ledger reader accepted an omitted original sibling")
	}
}
