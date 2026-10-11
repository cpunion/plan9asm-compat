package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeLayoutManifestPinsExactCandidates(t *testing.T) {
	root := filepath.Join("..", "..")
	ledger := filepath.Join(root, "testdata", "discovery", "ledger")
	skips, err := loadNativeLayoutSkips(root, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(skips) != 4 {
		t.Fatalf("native-layout skips = %d, want four exact candidates", len(skips))
	}
	for _, key := range []string{
		"github.com/quasilyte/GopherJRE@v0.0.0-20250131090304-888098460476",
		"github.com/aabalke/gojit@v0.0.0-20260919011104-e8574bd413ce",
		"github.com/LamkasDev/sharkie@v0.0.0-20260919122514-0af66a893005",
		"github.com/lamkasdev/sharkie@v0.0.0-20260919122514-0af66a893005",
	} {
		if skips[key].AsmFile == "" || skips[key].ObjectHex == "" {
			t.Fatalf("missing exact native-layout evidence for %s", key)
		}
	}
}

func TestNativeLayoutProofRequiresSourceAndGoObjectBytes(t *testing.T) {
	dir := t.TempDir()
	work := t.TempDir()
	const source = "#include \"textflag.h\"\nTEXT ·raw(SB),NOSPLIT,$0-0\nBYTE $0x90\nRET\n"
	writeTestFile(t, filepath.Join(dir, "raw_amd64.s"), source)
	digest := sha256.Sum256([]byte(source))
	skip := discoveryNativeLayoutSkip{
		Module: "example.com/raw", Version: "v1.0.0",
		AsmFile: "raw_amd64.s", Targets: []string{"linux/amd64"},
		SourceSHA256: hex.EncodeToString(digest[:]),
		Symbol:       "raw", ObjectHex: "90",
		Reason: "byte-exact native entry", EvidenceURLs: []string{"https://example.com/raw"},
	}
	if err := verifyNativeLayoutSource(dir, skip); err != nil {
		t.Fatal(err)
	}
	if err := verifyNativeLayoutGoObject(context.Background(), work, dir, os.Environ(), skip); err != nil {
		t.Fatal(err)
	}
	skip.ObjectHex = "deaddead"
	if err := verifyNativeLayoutGoObject(context.Background(), work, dir, os.Environ(), skip); err == nil {
		t.Fatal("absent native object bytes were accepted")
	}
	skip.ObjectHex = "90"
	writeTestFile(t, filepath.Join(dir, "raw_amd64.s"), source+"\n")
	if err := verifyNativeLayoutSource(dir, skip); err == nil {
		t.Fatal("changed source was accepted")
	}
}

func TestNativeLayoutWitnessMustBelongToPinnedSymbol(t *testing.T) {
	dir := t.TempDir()
	work := t.TempDir()
	const source = "#include \"textflag.h\"\n" +
		"TEXT ·raw(SB),NOSPLIT,$0-0\nRET\n" +
		"TEXT ·other(SB),NOSPLIT,$0-0\nBYTE $0x90\nRET\n"
	writeTestFile(t, filepath.Join(dir, "raw_amd64.s"), source)
	digest := sha256.Sum256([]byte(source))
	skip := discoveryNativeLayoutSkip{
		AsmFile: "raw_amd64.s", Targets: []string{"linux/amd64"},
		SourceSHA256: hex.EncodeToString(digest[:]),
		Symbol:       "raw", ObjectHex: "90",
	}
	if err := verifyNativeLayoutGoObject(context.Background(), work, dir, os.Environ(), skip); err == nil {
		t.Fatal("witness from another TEXT was accepted")
	}
}

func TestNativeLayoutFiltersOnlyPinnedFileAndTarget(t *testing.T) {
	skip := discoveryNativeLayoutSkip{
		AsmFile: "jit_amd64.s", Targets: []string{"darwin/amd64"},
	}
	configs := []discoveryBuildConfiguration{{
		Targets:  []string{"darwin/amd64"},
		AsmFiles: []string{"jit_amd64.s", "helper_amd64.s"},
	}, {
		Targets:  []string{"linux/amd64"},
		AsmFiles: []string{"helper_amd64.s"},
	}}
	filtered, active, err := filterNativeLayoutConfigurations(configs, skip)
	if err != nil || !active || len(filtered) != 2 {
		t.Fatalf("filtered = %+v, active=%t, err=%v", filtered, active, err)
	}
	for _, config := range filtered {
		if containsDiscoveryString(config.Targets, skip.Targets[0]) &&
			containsDiscoveryString(config.AsmFiles, skip.AsmFile) {
			t.Fatal("pinned file and target remained selected")
		}
	}
	if !containsDiscoveryString(filtered[0].AsmFiles, "helper_amd64.s") ||
		!containsDiscoveryString(filtered[1].AsmFiles, "helper_amd64.s") {
		t.Fatal("other files or targets were excluded")
	}
}

func TestNativeLayoutFiltersEveryPinnedTarget(t *testing.T) {
	skip := discoveryNativeLayoutSkip{
		AsmFile: "jit_amd64.s",
		Targets: []string{"darwin/amd64", "linux/amd64", "windows/amd64"},
	}
	configs := []discoveryBuildConfiguration{{
		Targets:  []string{"darwin/amd64", "linux/amd64", "windows/amd64"},
		AsmFiles: []string{"jit_amd64.s", "helper_amd64.s"},
	}}
	filtered, active, err := filterNativeLayoutConfigurations(configs, skip)
	if err != nil || !active {
		t.Fatalf("filter multiple native targets: active=%t error=%v", active, err)
	}
	for _, config := range filtered {
		for _, target := range skip.Targets {
			if containsDiscoveryString(config.Targets, target) &&
				containsDiscoveryString(config.AsmFiles, skip.AsmFile) {
				t.Fatalf("pinned file remains on %s: %+v", target, config)
			}
		}
	}
	if !containsDiscoveryString(discoveryConfigurationAsmFiles(filtered), "helper_amd64.s") {
		t.Fatal("unrelated assembly was excluded")
	}
}

func TestNativeLayoutRequiresEverySelectedTarget(t *testing.T) {
	skip := discoveryNativeLayoutSkip{
		AsmFile: "jit_amd64.s",
		Targets: []string{"darwin/amd64"},
	}
	configs := []discoveryBuildConfiguration{{
		Targets:  []string{"darwin/amd64", "linux/amd64"},
		AsmFiles: []string{"jit_amd64.s"},
	}}
	if _, _, err := filterNativeLayoutConfigurations(configs, skip); err == nil {
		t.Fatal("native-layout source remained translatable on an unpinned target")
	}
}

func TestNativeLayoutCandidateIsNotPassed(t *testing.T) {
	skip := discoveryNativeLayoutSkip{
		Module: "example.com/asm", Version: "v1.0.0",
		AsmFile: "jit_amd64.s", Targets: []string{"darwin/amd64"},
		SourceSHA256: strings.Repeat("a", 64), Symbol: "jit", ObjectHex: "90",
		Reason: "byte-exact entry", EvidenceURLs: []string{"https://example.com/source"},
	}
	result := discoveryCorpusResult{
		Module: skip.Module, Version: skip.Version,
		Status:             discoveryStatusSkippedNativeLayout,
		DiscoveredAsmFiles: []string{skip.AsmFile, "helper_amd64.s"},
		ApplicableAsmFiles: []string{"helper_amd64.s"},
		BuildConfigurations: []discoveryBuildConfiguration{{
			Targets: []string{"darwin/amd64"}, AsmFiles: []string{"helper_amd64.s"},
		}},
		Translations: 1, NativeLayout: &skip,
	}
	result.NativeLayoutPlan = fixtureNativeLayoutPlan(t, &skip, result.DiscoveredAsmFiles, []string{"darwin/amd64"}, nil)
	report := discoveryCorpusReport{
		Targets:  []string{"darwin/amd64"},
		Selected: 1, SkippedNativeLayout: 1, Translations: 1,
		Results: []discoveryCorpusResult{result},
	}
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		t.Fatal(err)
	}
	if report.Passed != 0 {
		t.Fatal("native-layout candidate counted as passed")
	}
	report.Results[0].BuildConfigurations[0].AsmFiles = append(
		report.Results[0].BuildConfigurations[0].AsmFiles, skip.AsmFile,
	)
	if err := validateDiscoveryCorpusAccounting(report); err == nil {
		t.Fatal("native-layout file was also claimed as translated")
	}
	report.Results[0].BuildConfigurations[0].AsmFiles = []string{"helper_amd64.s"}
	report.Results[0].Translations = 2
	report.Translations = 2
	if err := validateDiscoveryCorpusAccounting(report); err == nil {
		t.Fatal("native-layout result claimed an untested translation")
	}
}

func TestNativeLayoutSkipSurvivesAuditedAssemblyLedger(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	root := t.TempDir()
	manifestDir := filepath.Join(root, "testdata", "corpus")
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		t.Fatal(err)
	}
	skip := discoveryNativeLayoutSkip{
		Module: "example.com/a", Version: "v1.0.0",
		AsmFile: "a_amd64.s", Targets: []string{"linux/amd64"},
		SourceSHA256: strings.Repeat("a", 64), Symbol: "a", ObjectHex: "90",
		Reason: "native layout", EvidenceURLs: []string{"https://example.com/source"},
	}
	plan := fixtureNativeLayoutPlan(t, &skip, []string{skip.AsmFile}, []string{"linux/amd64", "linux/arm64"}, nil)
	// The offline report fixture uses synthetic Go 1.27 provenance, even in
	// the root module's Go 1.20 compatibility lane. These headers contain no
	// release/experiment constraints; this is not external corpus evidence.
	plan.GoVersion = "go1.27.1"
	plan.ReleaseTags = nil
	for version := 1; version <= 27; version++ {
		plan.ReleaseTags = append(plan.ReleaseTags, fmt.Sprintf("go1.%d", version))
	}
	manifest := discoveryNativeLayoutManifest{SchemaVersion: 1, Skips: []discoveryNativeLayoutSkip{skip}}
	writeManifest := func() {
		t.Helper()
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(manifestDir, "native-layout.json"), string(data))
	}
	writeManifest()
	if _, err := collectDiscoveryProgress(ledger, reports,
		[]string{"linux/amd64", "linux/arm64"}, source, 2, root); err == nil {
		t.Fatal("pinned native-layout candidate was accepted as passed")
	}
	for shard := 0; shard < 2; shard++ {
		name := filepath.Join(reports, "shard-"+string(rune('0'+shard))+".json")
		report, err := readDiscoveryCorpusReport(name)
		if err != nil {
			t.Fatal(err)
		}
		for i := range report.Results {
			if report.Results[i].Module != skip.Module {
				continue
			}
			report.Results[i].Status = discoveryStatusSkippedNativeLayout
			report.Results[i].Translations = 0
			report.Results[i].OrdinarySelectionPlan = nil
			report.Results[i].BuildConfigurations, report.Results[i].ApplicableAsmFiles = nil, nil
			report.Results[i].NativeLayout = &skip
			report.Results[i].NativeLayoutPlan = plan
			report.Passed--
			report.Translations--
			report.SkippedNativeLayout++
			if err := writeDiscoveryCorpusReport(name, report); err != nil {
				t.Fatal(err)
			}
		}
	}
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2, root)
	if err != nil || !progress.Verified || progress.Passed != 1 || progress.SkippedNativeLayout != 1 {
		t.Fatalf("native-layout progress = %+v, %v", progress, err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := writeAssemblyLedger(output, progress, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	restored, err := readAssemblyLedger(output, progress.LedgerSHA256, strings.Repeat("c", 64))
	if err != nil || restored.SkippedNativeLayout != 1 {
		t.Fatalf("restored native-layout progress = %+v, %v", restored, err)
	}
	for _, mutate := range []func(*discoveryCandidateProgress){
		func(candidate *discoveryCandidateProgress) { candidate.NativeLayoutPlan = nil },
		func(candidate *discoveryCandidateProgress) { candidate.NativeLayoutPlan.BuildConfigurations = nil },
		func(candidate *discoveryCandidateProgress) { candidate.DiscoveredAsmFiles = nil },
	} {
		data, err := json.Marshal(restored)
		if err != nil {
			t.Fatal(err)
		}
		var invalid discoveryProgress
		if err := json.Unmarshal(data, &invalid); err != nil {
			t.Fatal(err)
		}
		for i := range invalid.Candidates {
			if invalid.Candidates[i].NativeLayout != nil {
				mutate(&invalid.Candidates[i])
			}
		}
		if err := validateAssemblyLedgerProgress(invalid); err == nil {
			t.Fatal("persisted native-layout ledger accepted missing or reduced pre-filter proof")
		}
	}
	manifest.Skips[0].ObjectHex = "91"
	writeManifest()
	if _, err := collectDiscoveryProgress(ledger, reports,
		[]string{"linux/amd64", "linux/arm64"}, source, 2, root); err == nil {
		t.Fatal("report with stale native-layout manifest was accepted")
	}
}
