package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func exactDiscoveryFixture(t *testing.T) (discoveryCorpusConfig, []discoveryCandidate) {
	t.Helper()
	return exactDiscoveryFixtureCount(t, 4)
}

func exactDiscoveryFixtureCount(t *testing.T, count int) (discoveryCorpusConfig, []discoveryCandidate) {
	t.Helper()
	root := t.TempDir()
	var candidates []discoveryCandidate
	for index := 0; len(candidates) < count; index++ {
		candidate := discoveryCandidate{
			Module: fmt.Sprintf("example.com/exact/%04d", index), Version: "v1.0.0",
			Architectures: []string{"amd64"}, AsmFiles: []string{"f_amd64.s"},
		}
		if discoveryCandidateShard(candidate, 64) == 36 {
			candidates = append(candidates, candidate)
		}
	}
	foreign := discoveryCandidate{
		Module: "example.com/foreign", Version: "v1.0.0",
		Architectures: []string{"amd64"}, AsmFiles: []string{"f_amd64.s"},
	}
	if discoveryCandidateShard(foreign, 64) == 36 {
		t.Fatal("foreign fixture accidentally belongs to shard 36")
	}
	candidates = append(candidates, foreign)
	ledger := filepath.Join(root, "ledger.jsonl")
	var records strings.Builder
	for _, candidate := range candidates {
		data, err := json.Marshal(discoveryRecord{Kind: "matched", Module: candidate.Module,
			Version: candidate.Version, Architectures: candidate.Architectures, AsmFiles: candidate.AsmFiles})
		if err != nil {
			t.Fatal(err)
		}
		records.Write(data)
		records.WriteByte('\n')
	}
	writeTestFile(t, ledger, records.String())
	return discoveryCorpusConfig{
		LedgerPath: ledger, RepoRoot: ".", ShardIndex: 36, ShardCount: 64,
		// These two targets have actual captured portable protocol fixtures.
		// The separate full-matrix failure test retains all eleven targets.
		Targets: []string{"linux/amd64", "linux/arm64"}, CandidateTimeout: time.Minute,
		ReportPath: filepath.Join(root, "shard-36.json"),
		captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
			return fixtureDiscoveryProvenance(t, ledger), nil
		},
	}, candidates
}

func TestDiscoveryExactCandidateCheckpointUsesFullBucket(t *testing.T) {
	cfg, candidates := exactDiscoveryFixtureCount(t, 10)
	for _, candidate := range candidates[1:10] {
		cfg.ExactCandidates = append(cfg.ExactCandidates, candidate.exactKey())
	}
	calls := 0
	cfg.runCandidate = func(cfg discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
		if calls == 0 || calls == 8 {
			report, err := readDiscoveryCorpusReport(cfg.ReportPath)
			if err != nil || !report.Partial || report.Selected != calls || report.CandidateTotal != 11 {
				t.Fatalf("checkpoint=%+v err=%v", report, err)
			}
		}
		calls++
		return exactDiscoveryPass(t, cfg, candidate)
	}
	if err := runDiscoveryCorpus(cfg); err != nil || calls != 9 {
		t.Fatalf("subset execution calls=%d err=%v", calls, err)
	}
	report, err := readDiscoveryCorpusReport(cfg.ReportPath)
	if err != nil || !report.Partial || report.Selected != 9 {
		t.Fatalf("terminal checkpoint=%+v err=%v", report, err)
	}
}

func TestDiscoveryExactCandidateCancellationAndCleanupErrorsStayFailed(t *testing.T) {
	for _, cause := range []error{context.Canceled, errors.New("clean discovery candidate workspace: permission denied")} {
		t.Run(cause.Error(), func(t *testing.T) {
			cfg, candidates := exactDiscoveryFixture(t)
			cfg.ExactCandidates = []string{candidates[2].exactKey()}
			var workspace string
			cfg.runCandidate = func(cfg discoveryCorpusConfig, _ discoveryCandidate, work string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
				workspace = filepath.Dir(work)
				checkpoint, err := readDiscoveryCorpusReport(cfg.ReportPath)
				if err != nil || !checkpoint.Partial || checkpoint.Selected != 0 {
					t.Fatalf("pre-error checkpoint=%+v err=%v", checkpoint, err)
				}
				return matrixReport{}, nil, nil, cause
			}
			if err := runDiscoveryCorpus(cfg); err == nil {
				t.Fatal("suppressed cancellation/cleanup failure")
			}
			report, err := readDiscoveryCorpusReport(cfg.ReportPath)
			if err != nil || report.Failed != 1 || report.Passed != 0 || report.NotApplicable != 0 || report.Results[0].Error != cause.Error() {
				t.Fatalf("error classification=%+v err=%v", report, err)
			}
			if _, err := os.Stat(workspace); !os.IsNotExist(err) {
				t.Fatalf("owned shard workspace outlived failed execution: %v", err)
			}
		})
	}
}

func TestDiscoveryExactCandidateFullBucketMatchesUnfilteredExecution(t *testing.T) {
	cfg, candidates := exactDiscoveryFixture(t)
	inputs := make(map[string]discoveryCorpusResult)
	for _, candidate := range candidates[:4] {
		// Reuse exactly the same captured archive bytes; separately creating
		// the fixture ZIP would change its physical SHA through timestamps.
		inputs[candidate.exactKey()] = fixtureOrdinaryPassedResult(t, candidate, cfg.Targets)
	}
	var reports []discoveryCorpusReport
	for _, exact := range []bool{false, true} {
		if exact {
			for index := 3; index >= 0; index-- {
				cfg.ExactCandidates = append(cfg.ExactCandidates, candidates[index].exactKey())
			}
		}
		cfg.runCandidate = func(cfg discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
			result := inputs[candidate.exactKey()]
			return fixtureProfileMatrix(t, result), result.ApplicableAsmFiles, result.BuildConfigurations, nil
		}
		if err := runDiscoveryCorpus(cfg); err != nil {
			t.Fatal(err)
		}
		report, err := readDiscoveryCorpusReport(cfg.ReportPath)
		if err != nil || report.Partial || report.Selected != 4 {
			t.Fatalf("full bucket report=%+v err=%v", report, err)
		}
		reports = append(reports, report)
	}
	if !reflect.DeepEqual(reports[0], reports[1]) {
		t.Fatal("explicit complete bucket changed unfiltered report semantics")
	}
}

func TestDiscoveryExactCandidateFlagAndRealCLIModes(t *testing.T) {
	key := "example.com/module@v1.0.0"
	var values discoveryExactCandidateFlags
	flags := flag.NewFlagSet("exact", flag.ContinueOnError)
	flags.Var(&values, "discovery-exact-candidate", "exact")
	if err := flags.Parse([]string{"-discovery-exact-candidate=" + key, "-discovery-exact-candidate=example.com/other@v2.0.0"}); err != nil || len(values) != 2 {
		t.Fatalf("repeatable flag=%v err=%v", values, err)
	}
	for _, invalid := range []string{key, "", "example.com/module", "@v1.0.0", "x@latest", "x@v1.0.0@extra", "x @v1.0.0", "x@v1.0.0\n"} {
		if err := values.Set(invalid); err == nil {
			t.Fatalf("accepted duplicate/malformed flag %q", invalid)
		}
	}
	for _, option := range []string{
		"-list", "-suite=curated", "-discovery-progress=reports", "-verify-discovery-reports=reports",
		"-assembly-ledger-status=ledger", "-write-assembly-ledger=ledger", "-compare-assembly-ledger=ledger",
		"-require-verified-assembly-ledger", "-discovery-targets=linux/amd64", "curated-without-ledger",
	} {
		t.Run(option, func(t *testing.T) {
			args := []string{"-discovery-exact-candidate=" + key}
			if option != "curated-without-ledger" {
				args = append(args, "-discovery-ledger=unused", option)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, err := runDiscoveryExactCandidateTestCLI(ctx, t.TempDir(), "1", args...)
			if err == nil || !strings.Contains(string(out), "requires unfiltered discovery production") {
				t.Fatalf("real CLI mode was not rejected: %v %s", err, out)
			}
		})
	}
}

func runDiscoveryExactCandidateTestCLI(ctx context.Context, dir, mode string, args ...string) ([]byte, error) {
	env := replaceEnv(os.Environ(), map[string]string{"PLAN9ASM_EXACT_CLI_HELPER": mode})
	return runCapturedCommandOutput(ctx, dir, env, os.Args[0],
		append([]string{"-test.run=^TestDiscoveryExactCandidateCLIHelper$", "--"}, args...)...)
}

func TestDiscoveryExactCandidateCLIDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	out, err := runDiscoveryExactCandidateTestCLI(ctx, t.TempDir(), "wait-for-deadline")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CLI deadline was not preserved: error=%v output=%q", err, out)
	}
}

func TestDiscoveryExactCandidateCLIHelper(t *testing.T) {
	if os.Getenv("PLAN9ASM_EXACT_CLI_HELPER") == "wait-for-deadline" {
		// Finite even before the caller's deadline is enforced. This proves
		// the subprocess boundary without launching a real discovery request.
		time.Sleep(3 * time.Second)
		return
	}
	if os.Getenv("PLAN9ASM_EXACT_CLI_HELPER") != "1" {
		return
	}
	for index, arg := range os.Args {
		if arg == "--" {
			os.Args = append(os.Args[:1:1], os.Args[index+1:]...)
			flag.CommandLine = flag.NewFlagSet("plan9asmcorpus", flag.ExitOnError)
			main()
			t.Fatal("CLI mode unexpectedly returned")
		}
	}
	t.Fatal("missing helper argument boundary")
}

func TestDiscoveryExactCandidatePartialReaderRejectsForgedCompleteness(t *testing.T) {
	cfg, candidates := exactDiscoveryFixture(t)
	cfg.ExactCandidates = []string{candidates[2].exactKey()}
	cfg.runCandidate = func(cfg discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
		return exactDiscoveryPass(t, cfg, candidate)
	}
	if err := runDiscoveryCorpus(cfg); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(cfg.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nonpartial", "reduced total", "reduced eligible", "wrong shard", "wrong count", "unknown", "duplicate", "wrong files", "wrong targets", "stale tool"} {
		t.Run(name, func(t *testing.T) {
			var report discoveryCorpusReport
			if err := json.Unmarshal(original, &report); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "nonpartial":
				report.Partial = false
			case "reduced total":
				report.CandidateTotal = 1
			case "reduced eligible":
				report.EligibleCandidates = 1
			case "wrong shard":
				report.ShardIndex = 35
			case "wrong count":
				report.ShardCount = 65536
			case "unknown":
				report.Results[0].Module = "example.invalid/unknown"
			case "duplicate":
				report.Results = append(report.Results, report.Results[0])
				report.Selected++
				report.Passed++
				report.Translations *= 2
			case "wrong files":
				report.Results[0].DiscoveredAsmFiles = []string{"foreign.s"}
			case "wrong targets":
				report.Targets = []string{"linux/amd64"}
			case "stale tool":
				report.Provenance.TranslatorRevision = strings.Repeat("f", 40)
			}
			if err := writeDiscoveryCorpusReport(cfg.ReportPath, report); err != nil {
				t.Fatal(err)
			}
			if _, err := collectDiscoveryProgress(cfg.LedgerPath, cfg.ReportPath, cfg.Targets, report.Provenance.Source, 64); err == nil {
				t.Fatal("accepted forged focused inventory/proof")
			}
		})
	}
	var deleted discoveryCorpusReport
	if err := json.Unmarshal(original, &deleted); err != nil {
		t.Fatal(err)
	}
	deleted.Results = nil
	deleted.Selected, deleted.Passed, deleted.Translations = 0, 0, 0
	if err := writeDiscoveryCorpusReport(cfg.ReportPath, deleted); err != nil {
		t.Fatal(err)
	}
	progress, err := collectDiscoveryProgress(cfg.LedgerPath, cfg.ReportPath, cfg.Targets, deleted.Provenance.Source, 64)
	if err != nil || progress.Passed != 0 || progress.Pending != len(candidates) || progress.Complete || progress.Verified {
		t.Fatalf("paired deletion acquired completeness: %+v err=%v", progress, err)
	}
}

func TestDiscoveryExactCandidatePreservesProvenanceAndWriteFailures(t *testing.T) {
	for _, failure := range []string{"provenance", "publication"} {
		t.Run(failure, func(t *testing.T) {
			cfg, candidates := exactDiscoveryFixture(t)
			cfg.ExactCandidates = []string{candidates[2].exactKey()}
			captures := 0
			cfg.captureProvenance = func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
				captures++
				provenance := fixtureDiscoveryProvenance(t, cfg.LedgerPath)
				if failure == "provenance" && captures > 1 {
					provenance.Source.SHA256 = strings.Repeat("e", 64)
				}
				return provenance, nil
			}
			cfg.runCandidate = func(cfg discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
				if failure == "publication" {
					if err := os.Remove(cfg.ReportPath); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(cfg.ReportPath, 0755); err != nil {
						t.Fatal(err)
					}
				}
				return exactDiscoveryPass(t, cfg, candidate)
			}
			if err := runDiscoveryCorpus(cfg); err == nil {
				t.Fatal("focused execution suppressed terminal infrastructure failure")
			}
			if failure == "provenance" {
				report, err := readDiscoveryCorpusReport(cfg.ReportPath)
				if err != nil || report.Provenance.Invalidated == "" {
					t.Fatalf("invalidated report=%+v err=%v", report, err)
				}
				if _, err := collectDiscoveryProgress(cfg.LedgerPath, cfg.ReportPath, cfg.Targets, report.Provenance.Source, 64); err == nil {
					t.Fatal("invalidated selected-only proof passed readback")
				}
			}
		})
	}
}

func TestDiscoveryExactCandidateLibraryKeysUseNormalShard(t *testing.T) {
	for _, candidate := range []discoveryCandidate{
		{Module: "github.com/CWBudde/algo-fft", Version: "v0.8.0"},
		{Module: "github.com/Parquet-Go/Parquet-Go", Version: "v0.32.0"},
	} {
		if shard := discoveryCandidateShard(candidate, 64); shard != 36 {
			t.Fatalf("%s normal shard=%d, want 36", candidate.exactKey(), shard)
		}
	}
}

func exactDiscoveryPass(t *testing.T, cfg discoveryCorpusConfig, candidate discoveryCandidate) (matrixReport, []string, []discoveryBuildConfiguration, error) {
	t.Helper()
	result := fixtureOrdinaryPassedResult(t, candidate, cfg.Targets)
	return fixtureProfileMatrix(t, result), result.ApplicableAsmFiles, result.BuildConfigurations, nil
}

func TestDiscoveryExactCandidateNonPrefixSubsetRetainsDenominator(t *testing.T) {
	cfg, candidates := exactDiscoveryFixture(t)
	cfg.ExactCandidates = []string{candidates[3].exactKey(), candidates[1].exactKey()}
	var seen []string
	cfg.runCandidate = func(cfg discoveryCorpusConfig, candidate discoveryCandidate, work string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
		if len(seen) == 0 {
			checkpoint, err := readDiscoveryCorpusReport(cfg.ReportPath)
			if err != nil || !checkpoint.Partial || checkpoint.Selected != 0 || checkpoint.CandidateTotal != len(candidates) {
				t.Fatalf("initial checkpoint=%+v err=%v", checkpoint, err)
			}
		}
		seen = append(seen, candidate.exactKey())
		return exactDiscoveryPass(t, cfg, candidate)
	}
	if err := runDiscoveryCorpus(cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{candidates[1].exactKey(), candidates[3].exactKey()}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("execution=%v, want exact non-prefix subset %v", seen, want)
	}
	report, err := readDiscoveryCorpusReport(cfg.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || report.Selected != 2 || report.CandidateTotal != len(candidates) ||
		report.EligibleCandidates != len(candidates) || report.TargetFiltered || !reflect.DeepEqual(report.Targets, cfg.Targets) {
		t.Fatalf("reduced or complete denominator: %+v", report)
	}
	progress, err := collectDiscoveryProgress(cfg.LedgerPath, cfg.ReportPath, cfg.Targets, report.Provenance.Source, 64)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Passed != 2 || progress.Pending != 3 || progress.Complete || progress.Verified ||
		len(progress.PendingShards) != 64 || !reflect.DeepEqual(progress.PartialShards, []int{36}) {
		t.Fatalf("focused execution became full coverage: %+v", progress)
	}
	if err := verifyDiscoveryCorpusReports(cfg.LedgerPath, cfg.ReportPath, cfg.Targets, report.Provenance.Source); err == nil {
		t.Fatal("complete verifier accepted selected-only execution")
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSHA := strings.Repeat("c", 64)
	if err := writeAssemblyLedger(output, progress, semanticSHA); err != nil {
		t.Fatal(err)
	}
	restored, err := readAssemblyLedger(output, progress.LedgerSHA256, semanticSHA)
	if err != nil || restored.Passed != 2 || restored.Pending != 3 || restored.Verified || len(restored.PendingShards) != 64 {
		t.Fatalf("ledger roundtrip=%+v err=%v", restored, err)
	}
}

func TestDiscoveryExactCandidateRejectsInvalidRequestsBeforeExecution(t *testing.T) {
	for _, name := range []string{"empty", "whitespace", "latest", "unknown", "wrong version", "case", "duplicate", "wrong shard", "target filter"} {
		t.Run(name, func(t *testing.T) {
			cfg, candidates := exactDiscoveryFixture(t)
			key := candidates[0].exactKey()
			cfg.ExactCandidates = []string{key}
			switch name {
			case "empty":
				cfg.ExactCandidates = []string{""}
			case "whitespace":
				cfg.ExactCandidates = []string{" " + key}
			case "latest":
				cfg.ExactCandidates = []string{candidates[0].Module + "@latest"}
			case "unknown":
				cfg.ExactCandidates = []string{"example.invalid/unknown@v1.0.0"}
			case "wrong version":
				cfg.ExactCandidates = []string{candidates[0].Module + "@v2.0.0"}
			case "case":
				cfg.ExactCandidates = []string{strings.ToUpper(key)}
			case "duplicate":
				cfg.ExactCandidates = []string{key, key}
			case "wrong shard":
				cfg.ExactCandidates = []string{candidates[4].exactKey()}
			case "target filter":
				cfg.FilterTargets = true
			}
			calls := 0
			cfg.runCandidate = func(discoveryCorpusConfig, discoveryCandidate, string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
				calls++
				return matrixReport{}, nil, nil, errors.New("invalid request reached execution")
			}
			if err := runDiscoveryCorpus(cfg); err == nil || calls != 0 {
				t.Fatalf("invalid request ran candidates: calls=%d err=%v", calls, err)
			}
			if _, err := os.Stat(cfg.ReportPath); !os.IsNotExist(err) {
				t.Fatalf("invalid request published a report: %v", err)
			}
		})
	}
}

func TestDiscoveryExactCandidateRetainsFullDefaultTargetsAndRealFailures(t *testing.T) {
	cfg, candidates := exactDiscoveryFixture(t)
	manifest, err := loadManifest(filepath.Join("..", "..", "testdata", "corpus", "reported-libraries.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = manifest.Targets
	cfg.ExactCandidates = []string{candidates[2].exactKey()}
	calls := 0
	cfg.runCandidate = func(observed discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
		calls++
		if candidate.exactKey() != cfg.ExactCandidates[0] || !reflect.DeepEqual(observed.Targets, manifest.Targets) {
			t.Fatalf("changed candidate/matrix: candidate=%s targets=%v", candidate.exactKey(), observed.Targets)
		}
		return matrixReport{}, nil, nil, errors.New("original fixture compiler failure")
	}
	if err := runDiscoveryCorpus(cfg); err == nil || calls != 1 {
		t.Fatalf("failed exact execution calls=%d err=%v", calls, err)
	}
	report, err := readDiscoveryCorpusReport(cfg.ReportPath)
	if err != nil || !report.Partial || report.Failed != 1 || report.Passed != 0 || len(report.Targets) != 11 || report.TargetFiltered {
		t.Fatalf("full-matrix failure report=%+v err=%v", report, err)
	}
	progress, err := collectDiscoveryProgress(cfg.LedgerPath, cfg.ReportPath, manifest.Targets, report.Provenance.Source, 64)
	if err != nil || progress.Failed != 1 || progress.Pending != 4 || progress.Verified {
		t.Fatalf("failure lost during progress: %+v err=%v", progress, err)
	}
}
