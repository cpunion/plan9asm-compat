package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProfileScopesFailClosedAcrossAggregateProgressAndLedger(t *testing.T) {
	for name, mutate := range map[string]func(*discoveryCorpusReport){
		"legacy schema": func(report *discoveryCorpusReport) { report.SchemaVersion = 9 },
		"legacy relabel without profiles": func(report *discoveryCorpusReport) {
			report.Results[0].FeatureProfiles = nil
		},
		"missing shared inventory":  func(report *discoveryCorpusReport) { report.FeatureInventory = nil },
		"missing profile dimension": func(report *discoveryCorpusReport) { report.Results[0].BuildConfigurations[0].ProfileID = "" },
		"reserved feature as custom tag": func(report *discoveryCorpusReport) {
			report.Results[0].BuildConfigurations[0].BuildTags = []string{"amd64.v3"}
		},
		"lost custom-tag dimension": func(report *discoveryCorpusReport) {
			report.Results[0].BuildConfigurations[0].BuildTags = []string{"unobserved_custom"}
		},
		"missing actual consumption": func(report *discoveryCorpusReport) { report.Results[0].FeatureConsumption = nil },
		"missing actual LLVM object": func(report *discoveryCorpusReport) { report.Results[0].FeatureConsumption[0].Outputs = nil },
		"missing actual CPP graph":   func(report *discoveryCorpusReport) { report.Results[0].FeatureConsumption[0].CPP[0].Inputs = nil },
		"different actual module version": func(report *discoveryCorpusReport) {
			report.Results[0].FeatureConsumption[0].Packages[0].ModuleVersion = "v99.0.0"
		},
		"local headers relabeled as original module": func(report *discoveryCorpusReport) {
			report.Results[0].FeatureConsumption[0].Packages[0].SourceRole = "owned_local_replace"
		},
		"same ID changed actual driver bytes": func(report *discoveryCorpusReport) {
			id := report.Results[0].FeatureProfiles[0].ID
			report.FeatureInventory.Observations[id].DriverSHA256 = strings.Repeat("e", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			ledger, reports, source := writeDiscoveryReportFixture(t)
			progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
			if err != nil {
				t.Fatal(err)
			}
			files, err := discoveryCorpusReportFiles(reports)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				report, err := readDiscoveryCorpusReport(file)
				if err != nil {
					t.Fatal(err)
				}
				if len(report.Results) == 0 {
					continue
				}
				mutate(&report)
				if err := writeDiscoveryCorpusReport(file, report); err != nil {
					t.Fatal(err)
				}
				if err := verifyDiscoveryCorpusReports(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source); err == nil {
					t.Fatal("aggregate accepted an omitted or relabeled profile scope")
				}
				if _, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2); err == nil {
					t.Fatal("progress accepted an omitted or relabeled profile scope")
				}
				// Rebuild the compact candidate with the exact same mutation. It
				// must fail independently, not just because a raw report failed.
				for index := range progress.Candidates {
					candidate := &progress.Candidates[index]
					if candidate.Module != report.Results[0].Module {
						continue
					}
					result := report.Results[0]
					candidate.BuildConfigurations = result.BuildConfigurations
					candidate.FeatureProfiles = result.FeatureProfiles
					candidate.FeatureConsumption = result.FeatureConsumption
				}
				progress.FeatureInventory = report.FeatureInventory
				if report.SchemaVersion == 9 {
					progress.SchemaVersion = 1
				}
				encoded, err := json.Marshal(progress)
				if err != nil {
					t.Fatal(err)
				}
				var replay discoveryProgress
				if err := json.Unmarshal(encoded, &replay); err != nil {
					t.Fatal(err)
				}
				if err := validateAssemblyLedgerProgress(replay); err == nil {
					t.Fatal("compact ledger accepted the same omitted or relabeled profile scope")
				}
				return
			}
			t.Fatal("fixture has no candidate")
		})
	}
}
