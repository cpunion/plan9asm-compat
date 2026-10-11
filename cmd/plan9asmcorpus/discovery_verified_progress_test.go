package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These are first-party reader fixtures, not external-library pass receipts.
// The subprocess calls the real CLI, including its flag and source guards.
func TestDiscoveryVerifiedProgressRealCLI(t *testing.T) {
	for _, name := range []string{"complete", "missing shard", "failed candidate", "ledger mismatch", "trailing report data"} {
		t.Run(name, func(t *testing.T) {
			root, source := verifiedProgressSourceFixture(t)
			ledger, reports, _ := writeDiscoveryReportFixture(t)
			targets := []string{"linux/amd64", "linux/arm64"}
			for shard := 0; shard < 2; shard++ {
				filename := filepath.Join(reports, "shard-"+strconv.Itoa(shard)+".json")
				report, err := readDiscoveryCorpusReport(filename)
				if err != nil {
					t.Fatal(err)
				}
				report.Provenance.Source = source
				if err := writeDiscoveryCorpusReport(filename, report); err != nil {
					t.Fatal(err)
				}
			}
			progress, err := collectDiscoveryProgress(ledger, reports, targets, source, 2, root)
			if err != nil {
				t.Fatal(err)
			}
			stored := filepath.Join(t.TempDir(), "assembly-ledger")
			storedProgress := progress
			if name == "ledger mismatch" {
				filename := filepath.Join(reports, "shard-1.json")
				original, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				failVerifiedProgressFixtureCandidate(t, filename)
				storedProgress, err = collectDiscoveryProgress(ledger, reports, targets, source, 2, root)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filename, string(original))
			}
			if err := writeAssemblyLedger(stored, storedProgress, source.SHA256); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(reports, "shard-1.json")
			switch name {
			case "missing shard":
				if err := os.Remove(filename); err != nil {
					t.Fatal(err)
				}
			case "failed candidate":
				failVerifiedProgressFixtureCandidate(t, filename)
			case "trailing report data":
				data, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filename, string(data)+"{}\n")
			}
			manifest := corpusManifest{SchemaVersion: 1, Targets: targets, Libraries: []libraryManifest{{
				ID: "fixture", Origin: originEcosystemScan, Module: "example.com/a", Version: "v1.0.0",
				Inventory: map[string]expectedInventory{"linux/amd64": {AsmFiles: 1, Packages: []string{"example.com/a"}}},
			}}}
			manifestPath := filepath.Join(t.TempDir(), "manifest.json")
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, manifestPath, string(data))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			progressPath := filepath.Join(t.TempDir(), "assembly-progress.json")
			stdout, stderr, err := runVerifiedProgressCLI(ctx, root,
				"-manifest="+manifestPath, "-repo-root="+root, "-discovery-ledger="+ledger,
				"-verify-discovery-reports="+reports, "-compare-assembly-ledger="+stored,
				"-discovery-progress-output="+progressPath)
			if name == "complete" {
				if err != nil || !strings.Contains(string(stdout), "verified discovery corpus reports") {
					t.Fatalf("complete gate: %v stderr=%s", err, stderr)
				}
			} else if err == nil {
				t.Fatalf("%s passed the strict gate", name)
			}
			if name == "trailing report data" {
				if _, statErr := os.Stat(progressPath); !os.IsNotExist(statErr) ||
					!strings.Contains(string(stderr), "more than one JSON value") {
					t.Fatalf("unaudited report emitted progress: %q %s", stdout, stderr)
				}
				return
			}
			data, err = os.ReadFile(progressPath)
			if err != nil {
				t.Fatalf("audited progress was lost: %v stdout=%q stderr=%s", err, stdout, stderr)
			}
			var observed discoveryProgress
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&observed); err != nil {
				t.Fatalf("audited progress was lost: %v stdout=%q stderr=%s", err, stdout, stderr)
			}
			if err := ensureJSONEOF(decoder); err != nil {
				t.Fatal(err)
			}
			if observed.Source != source || observed.CandidateTotal != 2 {
				t.Fatalf("wrong audited inventory: %+v", observed)
			}
			if name == "missing shard" && (observed.Complete || observed.Verified || observed.Pending != 2) {
				t.Fatalf("missing work was promoted: %+v", observed)
			}
			if name == "failed candidate" && (observed.Verified || observed.Failed != 1) {
				t.Fatalf("failure was promoted: %+v", observed)
			}
		})
	}
}

func failVerifiedProgressFixtureCandidate(t *testing.T, filename string) {
	t.Helper()
	report, err := readDiscoveryCorpusReport(filename)
	if err != nil || len(report.Results) == 0 {
		t.Fatalf("candidate fixture: %v", err)
	}
	report.Results[0].Status = discoveryStatusFailed
	report.Results[0].Error = "first-party translation failure"
	report.Passed--
	report.Failed++
	if err := writeDiscoveryCorpusReport(filename, report); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryVerifiedProgressRejectsOtherModes(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-list"},
		{"-verify-discovery-reports=unused", "-list"},
		{"-verify-discovery-reports=unused", "-suite=curated"},
		{"-discovery-progress=unused"},
		{"-assembly-ledger-status=unused"},
		{"-discovery-ledger=unused", "-discovery-exact-candidate=example.com/a@v1.0.0"},
		{"-verify-discovery-reports=unused", "-discovery-events=unused"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stdout, stderr, err := runVerifiedProgressCLI(ctx, t.TempDir(),
				append(args, "-discovery-progress-output="+filepath.Join(t.TempDir(), "assembly-progress.json"))...)
			if err == nil || len(stdout) != 0 || !strings.Contains(string(stderr), "requires") {
				t.Fatalf("other CLI mode accepted: %v stdout=%q stderr=%s", err, stdout, stderr)
			}
		})
	}
}

func verifiedProgressSourceFixture(t *testing.T) (string, discoverySourceIdentity) {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "source.txt"), "first-party immutable reader fixture\n")
	writeTestFile(t, filepath.Join(root, "translator.json"), `{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`+"\n")
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"commit", "-qm", "fixture"}} {
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
			"-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + filepath.Join(root, "no-hooks")}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, output)
		}
	}
	source, err := collectDiscoverySource(root)
	if err != nil || source.Dirty {
		t.Fatalf("source fixture: %+v %v", source, err)
	}
	return root, source
}

func runVerifiedProgressCLI(ctx context.Context, root string, args ...string) ([]byte, []byte, error) {
	env := replaceEnv(os.Environ(), map[string]string{"PLAN9ASM_VERIFIED_PROGRESS_CLI_HELPER": "1"})
	return runDiscoveryMachineCommand(ctx, root, env, os.Args[0],
		append([]string{"-test.run=^TestDiscoveryVerifiedProgressCLIHelper$", "--"}, args...)...)
}

func TestDiscoveryVerifiedProgressCLIHelper(t *testing.T) {
	if os.Getenv("PLAN9ASM_VERIFIED_PROGRESS_CLI_HELPER") != "1" {
		return
	}
	for index, arg := range os.Args {
		if arg == "--" {
			os.Args = append(os.Args[:1:1], os.Args[index+1:]...)
			flag.CommandLine = flag.NewFlagSet("plan9asmcorpus", flag.ExitOnError)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing helper argument boundary")
}
