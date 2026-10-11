package main

import (
	"encoding/json"
	"os"

	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestOrdinaryPartialPackageRegistrationPortableGuards(t *testing.T) {
	candidate := discoveryCandidate{
		Module: "example.com/partial", Version: "v1.0.0",
		AsmFiles: []string{"bad_amd64.s", "good_amd64.s"},
	}
	plan := fixtureOrdinarySelectionForCandidate(t, candidate, []string{"linux/amd64"}, map[string]string{
		"go.mod":       "module example.com/partial\n",
		"probe.go":     "package partial\nfunc Bad(x uint64) uint64\nfunc Good() uint64\n",
		"bad_amd64.s":  "TEXT ·Bad(SB),4,$0-8\nRET\n",
		"good_amd64.s": "TEXT ·Good(SB),4,$0-8\nMOVQ $7,ret+0(FP)\nRET\n",
	})
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: []string{"good_amd64.s"},
		BuildConfigurations: []discoveryBuildConfiguration{{Targets: plan.Targets, AsmFiles: []string{"good_amd64.s"}}},
		Translations:        1, OrdinarySelectionPlan: plan,
		SourceNotApplicableItems: []discoverySourceNotApplicableItem{{
			AsmFiles: []string{"bad_amd64.s"}, Targets: plan.Targets,
			Kind:   discoverySourceNotApplicableAsmDecl,
			Reason: "bad_amd64.s:1: [amd64] Bad: wrong argument size 8; expected $...-16",
		}},
	}
	inventory := &discoveryFeatureInventory{}
	fixtureProfileEvidence(t, &result, inventory)
	validate := func(r discoveryCorpusResult) error {
		return validateOrdinaryProfileResult(r, plan.Targets, plan.GoVersion)
	}
	if err := validate(result); err != nil {
		t.Fatal(err)
	}
	checkPartialPackageReportReaders(t, result, inventory)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*discoveryCorpusResult){
		"missing registration": func(r *discoveryCorpusResult) { r.FeatureConsumption[0].RegisteredAsmFiles = nil },
		"duplicate registration": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].RegisteredAsmFiles = []string{"bad_amd64.s", "bad_amd64.s", "good_amd64.s"}
		},
		"unselected registration": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].RegisteredAsmFiles = []string{"bad_amd64.s", "good_amd64.s", "ignored_arm64.s"}
		},
		"missing diagnostic":            func(r *discoveryCorpusResult) { r.SourceNotApplicableItems = nil },
		"registration without output":   func(r *discoveryCorpusResult) { r.FeatureConsumption[0].Outputs = nil },
		"registration without consumer": func(r *discoveryCorpusResult) { r.FeatureConsumption = nil },
		"wrong consumption tags":        func(r *discoveryCorpusResult) { r.FeatureConsumption[0].CustomTags = []string{"alternate"} },
		"wrong target":                  func(r *discoveryCorpusResult) { r.BuildConfigurations[0].Targets = []string{"darwin/amd64"} },
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			change(&changed)
			if err := validate(changed); err == nil {
				t.Fatal("partial package proof was weakened by relabeling its registration")
			}
		})
	}
	profiles, err := resolveDiscoveryFeatureProfiles(inventory, result.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	input := ordinaryProfileConsumerInput(plan, profiles[0], candidate.Module, "", []string{"good_amd64.s"})
	for name, change := range map[string]func(*gotoolprofile.ConsumerInput){
		"missing registration":  func(in *gotoolprofile.ConsumerInput) { in.RegisteredAsmFiles = nil },
		"missing sibling":       func(in *gotoolprofile.ConsumerInput) { in.RegisteredAsmFiles = []string{"good_amd64.s"} },
		"unsorted registration": func(in *gotoolprofile.ConsumerInput) { in.RegisteredAsmFiles = []string{"good_amd64.s", "bad_amd64.s"} },
		"duplicate registration": func(in *gotoolprofile.ConsumerInput) {
			in.RegisteredAsmFiles = []string{"bad_amd64.s", "bad_amd64.s", "good_amd64.s"}
		},
		"foreign translation": func(in *gotoolprofile.ConsumerInput) { in.AsmFiles = []string{"foreign_amd64.s"} },
	} {
		t.Run("actual selection/"+name, func(t *testing.T) {
			copied := *input
			change(&copied)
			if err := gotoolprofile.ValidatePackageSelection(&copied, result.FeatureConsumption[0].Packages, nil); err == nil {
				t.Fatal("actual nonempty package selection escaped the complete registration guard")
			}
		})
	}
}

func checkPartialPackageReportReaders(t *testing.T, result discoveryCorpusResult, inventory *discoveryFeatureInventory) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := os.MkdirAll(filepath.Join(ledger, "records"), 0755); err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(discoveryRecord{
		Kind: "matched", Module: result.Module, Version: result.Version,
		Architectures: []string{"amd64"}, AsmFiles: result.DiscoveredAsmFiles,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(ledger, "records", "00.jsonl"), string(record)+"\n")
	provenance := fixtureDiscoveryProvenance(t, ledger)
	report := discoveryCorpusReport{
		SchemaVersion: discoveryReportSchema, Provenance: provenance,
		Targets: result.OrdinarySelectionPlan.Targets, ShardCount: 1,
		CandidateTotal: 1, EligibleCandidates: 1, Selected: 1, Passed: 1,
		Translations: result.Translations, Results: []discoveryCorpusResult{result}, FeatureInventory: inventory,
	}
	reports := t.TempDir()
	filename := filepath.Join(reports, "shard-0.json")
	if err := writeDiscoveryCorpusReport(filename, report); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, report.Targets, provenance.Source); err != nil {
		t.Fatalf("complete partial-package aggregate: %v", err)
	}
	progress, err := collectDiscoveryProgress(ledger, reports, report.Targets, provenance.Source, 1)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := discoveryFeatureBytesSHA256([]byte("synthetic semantic source"))
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	replayed, err := readAssemblyLedger(output, progress.LedgerSHA256, semanticSource)
	if err != nil || !replayed.Verified || len(replayed.Candidates) != 1 ||
		!equalDiscoveryStrings(replayed.Candidates[0].FeatureConsumption[0].RegisteredAsmFiles, result.DiscoveredAsmFiles) {
		t.Fatalf("compact ledger lost the separate complete package registration: %v", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	progressBytes, err := json.Marshal(progress)
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"registration", "source diagnostic", "object"} {
		t.Run("strict readers/"+missing, func(t *testing.T) {
			var changed discoveryCorpusReport
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			var compact discoveryProgress
			if err := json.Unmarshal(progressBytes, &compact); err != nil {
				t.Fatal(err)
			}
			switch missing {
			case "registration":
				changed.Results[0].FeatureConsumption[0].RegisteredAsmFiles = nil
				compact.Candidates[0].FeatureConsumption[0].RegisteredAsmFiles = nil
			case "source diagnostic":
				changed.Results[0].SourceNotApplicableItems = nil
				compact.Candidates[0].SourceNotApplicableItems = nil
			case "object":
				changed.Results[0].FeatureConsumption[0].Outputs = nil
				compact.Candidates[0].FeatureConsumption[0].Outputs = nil
			}
			if err := writeDiscoveryCorpusReport(filename, changed); err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryCorpusReports(ledger, reports, report.Targets, provenance.Source); err == nil {
				t.Fatal("aggregate promoted an incomplete partial-package proof")
			}
			if _, err := collectDiscoveryProgress(ledger, reports, report.Targets, provenance.Source, 1); err == nil {
				t.Fatal("progress promoted an incomplete partial-package proof")
			}
			if err := validateAssemblyLedgerProgress(compact); err == nil {
				t.Fatal("compact ledger promoted an incomplete partial-package proof")
			}
		})
	}
}
