package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryExceptionPreflightRejectsDuplicateBeforeMissingFile(t *testing.T) {
	ledger, selected := writeDiscoveryForeignPayloadLedger(t, true, 1)
	root := t.TempDir()
	writeDiscoveryInventoryExceptionManifests(t, root, ledger, selected.exactKey())
	for _, kind := range []string{"private-extensions", "native-layout"} {
		t.Run(kind, func(t *testing.T) {
			name := filepath.Join(root, "testdata", "corpus", kind+".json")
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]json.RawMessage
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			var skips []map[string]any
			if err := json.Unmarshal(manifest["skips"], &skips); err != nil {
				t.Fatal(err)
			}
			second := make(map[string]any, len(skips[0]))
			for key, value := range skips[0] {
				second[key] = value
			}
			second["asm_file"] = "missing.s"
			manifest["skips"], err = json.Marshal(append(skips, second))
			if err != nil {
				t.Fatal(err)
			}
			data, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, name, string(data))
			if kind == "private-extensions" {
				_, err = loadPrivateExtensionSkips(root, ledger)
			} else {
				_, err = loadNativeLayoutSkips(root, ledger)
			}
			if err == nil || !strings.Contains(err.Error(), "duplicate ") {
				t.Fatalf("duplicate manifest changed into missing-file/other diagnosis: %v", err)
			}
		})
	}
}

func TestDiscoveryExceptionPreflightAcceptsValidEmptyManifests(t *testing.T) {
	ledger, selected := writeDiscoveryForeignPayloadLedger(t, true, 1)
	root := t.TempDir()
	writeDiscoveryInventoryExceptionManifests(t, root, ledger, selected.exactKey())
	for _, name := range []string{"private-extensions.json", "native-layout.json"} {
		writeTestFile(t, filepath.Join(root, "testdata", "corpus", name), `{"schema_version":1,"skips":[]}`)
	}
	if got, err := loadPrivateExtensionSkips(root, ledger); err != nil || len(got) != 0 {
		t.Fatalf("valid empty private manifest failed: %v, %v", got, err)
	}
	if got, err := loadNativeLayoutSkips(root, ledger); err != nil || len(got) != 0 {
		t.Fatalf("valid empty native manifest failed: %v, %v", got, err)
	}
}

func TestDiscoveryExceptionPreflightKeepsGlobalMembershipWhenTargetFiltered(t *testing.T) {
	cfg, candidates := exactDiscoveryFixtureCount(t, 1)
	cfg.RepoRoot = t.TempDir()
	writeDiscoveryInventoryExceptionManifests(t, cfg.RepoRoot, cfg.LedgerPath, candidates[0].exactKey())
	cfg.FilterTargets = true
	cfg.Targets = []string{"js/wasm"}
	cfg.runCandidate = func(discoveryCorpusConfig, discoveryCandidate, string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
		t.Fatal("filename-ineligible candidate was executed")
		return matrixReport{}, nil, nil, nil
	}
	if err := runDiscoveryCorpus(cfg); err != nil {
		t.Fatal(err)
	}
	report, err := readDiscoveryCorpusReport(cfg.ReportPath)
	if err != nil || report.CandidateTotal != 2 || report.EligibleCandidates != 0 ||
		report.Selected != 0 || report.Passed != 0 || report.NotApplicable != 0 || report.Partial {
		t.Fatalf("filtered empty bucket invented outcome/lost global membership: %+v, %v", report, err)
	}
}
