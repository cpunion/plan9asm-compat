package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssemblyLedgerPersistsAuditedProgress(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatalf("idempotent update: %v", err)
	}
	got, err := readAssemblyLedger(output, progress.LedgerSHA256, semanticSource)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete || !got.Verified || got.Passed != 2 || got.CandidateTotal != 2 || len(got.Candidates) != 2 {
		t.Fatalf("assembly ledger = %+v", got)
	}
	for _, candidate := range got.Candidates {
		if candidate.Status != discoveryStatusPassed {
			t.Fatalf("candidate = %+v", candidate)
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"translations":1`) {
			t.Fatalf("passed candidate lost compilation count: %s", data)
		}
	}
	if _, err := readAssemblyLedger(output, strings.Repeat("b", 64), semanticSource); err == nil {
		t.Fatal("stale scan ledger accepted")
	}
	if _, err := readAssemblyLedger(output, progress.LedgerSHA256, strings.Repeat("b", 64)); err == nil {
		t.Fatal("stale source accepted")
	}
}

func TestAssemblyLedgerSemanticSourceExcludesOnlyItsEvidence(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v: %s", err, output)
	}
	writeTestFile(t, filepath.Join(root, "translator.go"), "package translator\n")
	before, err := collectDiscoverySemanticSourceSHA(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "testdata", "discovery", "assembly-ledger"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "testdata", "discovery", "assembly-ledger", "manifest.json"), "{}\n")
	afterEvidence, err := collectDiscoverySemanticSourceSHA(root)
	if err != nil {
		t.Fatal(err)
	}
	if afterEvidence != before {
		t.Fatal("assembly evidence changed semantic source fingerprint")
	}
	writeTestFile(t, filepath.Join(root, "translator.go"), "package changed\n")
	afterSource, err := collectDiscoverySemanticSourceSHA(root)
	if err != nil {
		t.Fatal(err)
	}
	if afterSource == before {
		t.Fatal("translator change did not invalidate assembly evidence")
	}
}

func TestAssemblyLedgerKeepsMissingReportsPending(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	if err := os.Remove(filepath.Join(reports, "shard-1.json")); err != nil {
		t.Fatal(err)
	}
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := writeAssemblyLedger(output, progress, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	got, err := readAssemblyLedger(output, progress.LedgerSHA256, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified || got.Complete || got.Passed != progress.Passed || got.Pending != progress.Pending {
		t.Fatalf("partial assembly ledger = %+v", got)
	}
	if got.Pending == 0 {
		t.Fatal("missing report did not leave any candidate pending")
	}
	if err := requireVerifiedAssemblyLedger(got); err == nil {
		t.Fatal("pending candidates satisfied the strict completion gate")
	}
}

func TestAssemblyLedgerCompletionGateAcceptsAuditedOutcomes(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireVerifiedAssemblyLedger(progress); err != nil {
		t.Fatal(err)
	}
	progress.Failed = 1
	progress.Verified = false
	if err := requireVerifiedAssemblyLedger(progress); err == nil {
		t.Fatal("failed candidate satisfied the strict completion gate")
	}
}

func TestAssemblyLedgerRejectsUnexplainedOrUncompiledOutcome(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*discoveryProgress)
	}{
		{
			name: "pass without translation",
			change: func(p *discoveryProgress) {
				p.Candidates[0].Translations = 0
				p.Translations--
			},
		},
		{
			name: "source skip without reason",
			change: func(p *discoveryProgress) {
				p.Candidates[0].Status = discoveryStatusNotApplicable
				p.Candidates[0].Translations = 0
				p.Passed--
				p.NotApplicable++
				p.Translations--
			},
		},
		{
			name: "target skip without per-file evidence",
			change: func(p *discoveryProgress) {
				p.Candidates[0].NotApplicableTranslations = 1
				p.NotApplicableTranslations = 1
			},
		},
		{
			name: "target skip with absolute runner path",
			change: func(p *discoveryProgress) {
				p.Candidates[0].NotApplicableTranslations = 1
				p.NotApplicableTranslations = 1
				item := matrixTargetNotApplicableItem{
					Target: "linux/amd64",
					targetNotApplicableItem: targetNotApplicableItem{
						PkgPath: "example.com/asm", AsmFile: "/tmp/runner/stub.s",
						Kind: targetNotApplicableGoTextArgSize, Symbol: "example.com/asm.stub",
						DeclaredArgSize: 16, ExpectedArgSize: 8,
					},
				}
				item.Reason = discoveryTargetSkipReason(item)
				p.Candidates[0].NotApplicableItems = []matrixTargetNotApplicableItem{item}
			},
		},
		{
			name: "source skip with raw diagnostic",
			change: func(p *discoveryProgress) {
				p.Candidates[0].SourceNotApplicableItems = []discoverySourceSkipSummary{{
					AsmFile: "a_amd64.s",
					Targets: []string{"linux/amd64"},
					Kind:    discoverySourceNotApplicableGoBuild,
					Reason:  "build failed at /tmp/ephemeral/cache/file.go",
				}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := progress
			changed.Candidates = append([]discoveryCandidateProgress(nil), progress.Candidates...)
			tc.change(&changed)
			if err := validateAssemblyLedgerProgress(changed); err == nil {
				t.Fatal("accepted assembly outcome without required evidence")
			}
			if err := requireVerifiedAssemblyLedger(changed); err == nil {
				t.Fatal("completion gate trusted summary flags instead of candidate evidence")
			}
		})
	}
}

func TestAssemblyLedgerMatchesCurrentCorpusReports(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	stored, err := readAssemblyLedger(output, progress.LedgerSHA256, semanticSource)
	if err != nil {
		t.Fatal(err)
	}
	current := progress
	current.Source.Revision = strings.Repeat("b", 40)
	if err := compareAssemblyLedgerProgress(stored, current); err != nil {
		t.Fatalf("same semantic source with evidence-only revision change: %v", err)
	}
	current.Candidates = append([]discoveryCandidateProgress(nil), current.Candidates...)
	current.Candidates[0].Translations++
	if err := compareAssemblyLedgerProgress(stored, current); err == nil {
		t.Fatal("ledger accepted a different candidate compilation result")
	}
	current = progress
	current.Pending = 1
	current.Verified = false
	if err := compareAssemblyLedgerProgress(stored, current); err == nil {
		t.Fatal("ledger accepted incomplete current reports")
	}
}

func TestAssemblyLedgerRejectsTamperedShard(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	shards, err := filepath.Glob(filepath.Join(output, "records", "*.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("record shards = %v, %v", shards, err)
	}
	if err := os.WriteFile(shards[0], []byte(`{"module":"example.com/forged","version":"v1.0.0","status":"passed"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAssemblyLedger(output, progress.LedgerSHA256, semanticSource); err == nil {
		t.Fatal("tampered record shard accepted")
	}
}

func TestAssemblyLedgerRefusesUnrecognizedExistingDirectory(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(output, "unrelated.txt")
	writeTestFile(t, marker, "keep me\n")
	if err := writeAssemblyLedger(output, progress, strings.Repeat("a", 64)); err == nil {
		t.Fatal("overwrote an unrecognized directory")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "keep me\n" {
		t.Fatalf("unrecognized directory was modified: %q, %v", data, err)
	}
}

func TestAssemblyLedgerRefusesBroadDestination(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"/", t.TempDir(), filepath.Join(t.TempDir(), "ledger")} {
		if err := writeAssemblyLedger(output, progress, strings.Repeat("a", 64)); err == nil {
			t.Fatalf("accepted unsafe destination %q", output)
		}
	}
}

func TestAssemblyLedgerDestinationDoesNotOverlapScanInput(t *testing.T) {
	root := t.TempDir()
	scan := filepath.Join(root, "ledger")
	for _, output := range []string{
		scan,
		filepath.Join(scan, "assembly-ledger"),
		root,
	} {
		if err := validateAssemblyLedgerDestination(scan, output); err == nil {
			t.Fatalf("accepted overlapping destination %q", output)
		}
	}
	if err := validateAssemblyLedgerDestination(scan, filepath.Join(root, "assembly-ledger")); err != nil {
		t.Fatal(err)
	}
}
