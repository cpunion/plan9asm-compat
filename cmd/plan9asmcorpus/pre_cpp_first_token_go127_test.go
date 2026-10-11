//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrdinaryPreCPPFirstTokenDefaultTargetsAndStrictReaders(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/first-token", Version: "v1.0.0",
		AsmFiles: []string{"docs/foreign.s"}}
	sources := map[string]string{
		"go.mod":         "module example.invalid/first-token\n\ngo 1.20\n",
		"docs/main.go":   "package main\nfunc main() {}\n",
		"docs/foreign.s": ".section .text\nmov r0, #1\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	targets := []string{"darwin/amd64", "darwin/arm64", "linux/386", "linux/amd64", "linux/arm", "linux/arm64",
		"windows/386", "windows/amd64", "windows/arm64", "js/wasm", "wasip1/wasm"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	plan, profiles, configurations, exclusions, root, err := captureDiscoveryOrdinaryProfiles(ctx,
		candidate, download, targets, t.TempDir(), os.Environ())
	if err != nil {
		t.Fatalf("actual first-token Go rejection blocked before CPP planning: %v", err)
	}
	if len(configurations) != 0 || len(exclusions) != len(targets) || len(plan.PreCPPRejections) != len(targets) || plan.CPPInputs != nil {
		t.Fatalf("foreign source became translation or lost target scopes: configs=%v exclusions=%d proofs=%d",
			configurations, len(exclusions), len(plan.PreCPPRejections))
	}
	for _, proof := range plan.PreCPPRejections {
		if proof.Protocol != discoveryPreCPPFirstTokenProtocol || proof.FirstToken != "." || proof.Directive != "" ||
			proof.Line != 1 || proof.ControlPrefix != ".section .text\n" || !preCPPExactSourceDiagnostic(proof) {
			t.Fatalf("source rejection lost its exact original token/prefix/actual diagnostic: %+v", proof)
		}
	}
	inventory := newDiscoveryFeatureInventory()
	references, err := registerDiscoveryFeatureProfiles(inventory, profiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusNotApplicable,
		DiscoveredAsmFiles: candidate.AsmFiles, OrdinarySelectionPlan: plan, FeatureProfiles: references,
		SourceNotApplicableItems: exclusions, featureInventory: inventory,
		NotApplicableReason: ordinarySelectionReason(plan, exclusions, nil)}
	if err := validateOrdinaryProfileResult(result, targets, plan.GoVersion); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"missing token": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections[0].FirstToken = "" },
		"changed token": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections[0].FirstToken = "42" },
		"historical protocol": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].Protocol = discoveryPreCPPRejectionProtocol
		},
		"mixed token/control": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections[0].Directive = "section" },
		"prior control": func(r *discoveryCorpusResult) {
			p := &r.OrdinarySelectionPlan.PreCPPRejections[0]
			p.ControlPrefix, p.Line = "#ifdef NEVER\n.section .text\n", 2
			p.Reason = "docs/foreign.s:2: expected identifier, found \".\""
		},
		"ordinary first token": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].ControlPrefix = "TEXT ·Probe(SB),4,$0-0\n"
		},
		"unrelated diagnostic": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].Reason = "docs/foreign.s:1: unexpected token after '#': section"
		},
		"missing target": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections = r.OrdinarySelectionPlan.PreCPPRejections[1:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			mutate(&changed)
			if err := validateOrdinaryProfileResult(changed, targets, plan.GoVersion); err == nil {
				t.Fatal("forged first-token source rejection passed the independent reader")
			}
		})
	}
	checkFirstTokenReportReadback(t, candidate, targets, result, inventory)
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(download.Dir, "docs/foreign.s"), ".section .data\n")
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err == nil {
		t.Fatal("whole original assembly changed without invalidating its source rejection")
	}
}

func checkFirstTokenReportReadback(t *testing.T, candidate discoveryCandidate, targets []string,
	result discoveryCorpusResult, inventory *discoveryFeatureInventory) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "ledger.jsonl")
	record, err := json.Marshal(discoveryRecord{Kind: "matched", Module: candidate.Module, Version: candidate.Version, AsmFiles: candidate.AsmFiles})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, ledger, string(record)+"\n")
	provenance := fixtureDiscoveryProvenance(t, ledger)
	report := discoveryCorpusReport{SchemaVersion: discoveryReportSchema, Provenance: provenance, Targets: targets,
		CandidateTotal: 1, EligibleCandidates: 1, Selected: 1, NotApplicable: 1, ShardCount: 1,
		Results: []discoveryCorpusResult{result}, FeatureInventory: inventory}
	reports := t.TempDir()
	if err := writeDiscoveryCorpusReport(filepath.Join(reports, "shard-0.json"), report); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, targets, provenance.Source); err != nil {
		t.Fatal(err)
	}
	progress, err := collectDiscoveryProgress(ledger, reports, targets, provenance.Source, 1)
	if err != nil || progress.Passed != 0 || progress.NotApplicable != 1 || progress.Translations != 0 {
		t.Fatalf("foreign-source report became an assembly pass: %+v %v", progress, err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semantic := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semantic); err != nil {
		t.Fatal(err)
	}
	readback, err := readAssemblyLedger(output, progress.LedgerSHA256, semantic)
	if err != nil || readback.Passed != 0 || readback.NotApplicable != 1 || readback.Translations != 0 {
		t.Fatalf("foreign-source ledger became an assembly pass: %+v %v", readback, err)
	}
}
