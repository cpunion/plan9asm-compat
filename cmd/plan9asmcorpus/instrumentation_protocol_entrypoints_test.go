package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstrumentationProtocolFullReportEntryPointsRejectDowngradeAndMixedHistory(t *testing.T) {
	for _, mutation := range []string{"schema10 sibling", "delete stamp", "downgrade both", "delete both", "delete type marker", "v1 type marker", "paired type deletion"} {
		t.Run(mutation, func(t *testing.T) {
			ledger, reports, source := writeDiscoveryReportFixture(t)
			name := filepath.Join(reports, "shard-0.json")
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			var report discoveryCorpusReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "schema10 sibling":
				report.SchemaVersion = 10
			case "delete stamp":
				report.Provenance.InstrumentationScopeProtocol = ""
			case "downgrade both":
				report.Provenance.InstrumentationScopeProtocol = ""
				for index := range report.Results {
					report.Results[index].OrdinarySelectionPlan.InstrumentationPlan.Protocol = discoveryInstrumentationLegacyProtocol
				}
			case "delete both":
				report.Provenance.InstrumentationScopeProtocol = ""
				for index := range report.Results {
					report.Results[index].OrdinarySelectionPlan.InstrumentationPlan = nil
				}
			case "delete type marker":
				report.Provenance.InstrumentationTypeSourceProtocol = ""
			case "v1 type marker":
				report.Provenance.InstrumentationTypeSourceProtocol = "actual_go_instrumentation_type_sources_v1"
			case "paired type deletion":
				report.Provenance.InstrumentationTypeSourceProtocol = ""
				for index := range report.Results {
					for outcome := range report.Results[index].OrdinarySelectionPlan.InstrumentationPlan.Outcomes {
						report.Results[index].OrdinarySelectionPlan.InstrumentationPlan.Outcomes[outcome].TypeSources = nil
					}
				}
			}
			changed, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryCorpusReports(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source); err == nil {
				t.Fatal("full verification entrypoint admitted changed current/historical report")
			}
			if progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2); err == nil || progress.CandidateTotal != 0 {
				t.Fatal("full progress entrypoint returned plausible partial counts after protocol failure")
			}
		})
	}
}

func TestInstrumentationProtocolFullLedgerEntryPointKeepsV2Historical(t *testing.T) {
	progress := fixtureSemanticProgress(t)
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semantic := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semantic); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(output, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest assemblyLedgerManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Format, manifest.Progress.SchemaVersion = "module-hashed-assembly-ledger-v2", 2
	manifest.Progress.Provenance.InstrumentationScopeProtocol = ""
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAssemblyLedger(output, progress.LedgerSHA256, semantic); err == nil || !strings.Contains(err.Error(), "format or source/scan provenance is stale") {
		t.Fatalf("current full status/comparison reader promoted v2 history: %v", err)
	}
	if err := writeAssemblyLedger(output, progress, semantic); err == nil {
		t.Fatal("current writer silently migrated a v2 evidence snapshot")
	}
	after, err := os.ReadFile(manifestPath)
	if err != nil || string(after) != string(data) {
		t.Fatal("rejected historical snapshot was modified")
	}
}
