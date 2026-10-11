package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test executable can act as a narrow Git relay. It still runs the real
// Git command; the only injected operation changes a first-party input at the
// second source-status read, after the stored ledger comparison has finished.
func TestMain(m *testing.M) {
	if os.Getenv("PLAN9ASM_FROZEN_GIT_RELAY") == "1" &&
		strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") == "git" {
		if err := mutateFrozenAggregateFixture(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(97)
		}
		cmd := exec.Command(os.Getenv("PLAN9ASM_FROZEN_REAL_GIT"), os.Args[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				os.Exit(exit.ExitCode())
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(98)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func mutateFrozenAggregateFixture(args []string) error {
	if len(args) < 3 || args[2] != "status" {
		return nil
	}
	counter := os.Getenv("PLAN9ASM_FROZEN_GIT_COUNTER")
	count := 0
	data, err := os.ReadFile(counter)
	if err == nil {
		count, err = strconv.Atoi(string(data))
	} else if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		return err
	}
	count++
	if err := os.WriteFile(counter, []byte(strconv.Itoa(count)), 0600); err != nil {
		return err
	}
	if count != 2 {
		return nil
	}
	file, err := os.OpenFile(os.Getenv("PLAN9ASM_FROZEN_MUTATE"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString("\n")
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

type frozenAggregateFixture struct {
	root, ledger, reports, stored, manifest string
}

func newFrozenAggregateFixture(t *testing.T) frozenAggregateFixture {
	t.Helper()
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
	if err := writeAssemblyLedger(stored, progress, source.SHA256); err != nil {
		t.Fatal(err)
	}
	manifest := corpusManifest{SchemaVersion: 1, Targets: targets, Libraries: []libraryManifest{{
		ID: "fixture", Origin: originEcosystemScan, Module: "example.com/a", Version: "v1.0.0",
		Inventory: map[string]expectedInventory{"linux/amd64": {AsmFiles: 1, Packages: []string{"example.com/a"}}},
	}}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	writeTestFile(t, manifestPath, string(data))
	return frozenAggregateFixture{root, ledger, reports, stored, manifestPath}
}

func (fixture frozenAggregateFixture) args(output string) []string {
	return []string{
		"-manifest=" + fixture.manifest, "-repo-root=" + fixture.root,
		"-discovery-ledger=" + fixture.ledger, "-verify-discovery-reports=" + fixture.reports,
		"-compare-assembly-ledger=" + fixture.stored, "-discovery-progress-output=" + output,
	}
}

func TestDiscoveryVerifiedProgressFrozenInputs(t *testing.T) {
	for _, kind := range []string{"source", "scan ledger", "assembly ledger"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newFrozenAggregateFixture(t)
			mutation := filepath.Join(fixture.root, "source.txt")
			if kind == "scan ledger" {
				mutation = filepath.Join(fixture.ledger, "records", "00.jsonl")
			} else if kind == "assembly ledger" {
				entries, err := os.ReadDir(filepath.Join(fixture.stored, "records"))
				if err != nil || len(entries) == 0 {
					t.Fatalf("stored records: %v", err)
				}
				mutation = filepath.Join(fixture.stored, "records", entries[0].Name())
			}
			git, err := exec.LookPath("git")
			if err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			name := "git"
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			copyFrozenGitRelay(t, filepath.Join(bin, name))
			counter := filepath.Join(t.TempDir(), "status-count")
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("PLAN9ASM_FROZEN_GIT_RELAY", "1")
			t.Setenv("PLAN9ASM_FROZEN_REAL_GIT", git)
			t.Setenv("PLAN9ASM_FROZEN_GIT_COUNTER", counter)
			t.Setenv("PLAN9ASM_FROZEN_MUTATE", mutation)
			output := filepath.Join(t.TempDir(), "assembly-progress.json")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			stdout, stderr, err := runVerifiedProgressCLI(ctx, fixture.root, fixture.args(output)...)
			calls, readErr := os.ReadFile(counter)
			count, countErr := strconv.Atoi(string(calls))
			if readErr != nil || countErr != nil || count < 2 {
				t.Fatalf("mutation did not reach final source read: %q %v; %s", calls, readErr, stderr)
			}
			if err == nil || !strings.Contains(string(stderr), "changed") || len(stdout) != 0 {
				t.Fatalf("changed %s accepted: %v stdout=%q stderr=%s", kind, err, stdout, stderr)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("invalidated input published progress: %v", err)
			}
			entries, err := os.ReadDir(filepath.Dir(output))
			if err != nil || len(entries) != 0 {
				t.Fatalf("owned preparation leaked: %v %v", entries, err)
			}
		})
	}
}

func TestDiscoveryProgressDirectoryPreflightRealCLI(t *testing.T) {
	for _, name := range []string{
		"outside", "ignored output", "source", "scan ledger", "scan nested", "scan ancestor",
		"assembly ledger", "assembly nested", "assembly ancestor", "scan alias", "assembly alias",
		"unignored output", "source alias", "relative output",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFrozenAggregateFixture(t)
			writeTestFile(t, filepath.Join(fixture.root, ".gitignore"), "_out/\n")
			output := filepath.Join(t.TempDir(), "new", "reports")
			want := ""
			switch name {
			case "ignored output":
				output = filepath.Join(fixture.root, "_out", "new", "reports")
			case "source":
				output, want = filepath.Join(fixture.root, "new", "reports"), "ignored _out"
			case "scan ledger":
				output, want = fixture.ledger, "overlaps"
			case "scan nested":
				output, want = filepath.Join(fixture.ledger, "nested", "reports"), "overlaps"
			case "scan ancestor":
				output, want = filepath.Dir(fixture.ledger), "overlaps"
			case "assembly ledger":
				output, want = fixture.stored, "overlaps"
			case "assembly nested":
				output, want = filepath.Join(fixture.stored, "nested", "reports"), "overlaps"
			case "assembly ancestor":
				output, want = filepath.Dir(fixture.stored), "overlaps"
			case "scan alias", "assembly alias", "source alias":
				destination := fixture.ledger
				want = "overlaps"
				if name == "assembly alias" {
					destination = fixture.stored
				} else if name == "source alias" {
					destination, want = fixture.root, "ignored _out"
				}
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(destination, alias); err != nil {
					t.Fatal(err)
				}
				output = filepath.Join(alias, "new", "reports")
			case "unignored output":
				writeTestFile(t, filepath.Join(fixture.root, ".gitignore"), "")
				output, want = filepath.Join(fixture.root, "_out", "new", "reports"), "ignored _out"
			case "relative output":
				output = filepath.Join("_out", "new", "reports")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stdout, stderr, err := runVerifiedProgressCLI(ctx, fixture.root,
				"-repo-root="+fixture.root, "-discovery-ledger="+fixture.ledger,
				"-compare-assembly-ledger="+fixture.stored, "-discovery-progress-directory="+output)
			if want == "" {
				if err != nil || len(stdout) == 0 {
					t.Fatalf("safe directory rejected: %v stdout=%q stderr=%s", err, stdout, stderr)
				}
			} else if err == nil || len(stdout) != 0 || !strings.Contains(string(stderr), want) {
				t.Fatalf("unsafe directory accepted or wrong rejection: %v stdout=%q stderr=%s", err, stdout, stderr)
			}
			// The preflight must not create its destination or status files.
			physical := output
			if !filepath.IsAbs(physical) {
				physical = filepath.Join(fixture.root, physical)
			}
			if entries, err := os.ReadDir(physical); err == nil {
				for _, entry := range entries {
					if entry.Name() == "new" || entry.Name() == "scan-status.json" || entry.Name() == "assembly-progress.json" {
						t.Fatalf("preflight wrote destination: %s", entry.Name())
					}
				}
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
}

func TestDiscoveryProgressDirectoryModeRejectsExplicitEmptyAndOtherReaders(t *testing.T) {
	fixture := newFrozenAggregateFixture(t)
	// Older Go uses the complete test name as a TempDir basename. Keep names
	// bounded and independent of concrete filesystem paths in the arguments.
	for _, test := range []struct {
		name string
		args []string
	}{
		{"empty directory with list", []string{"-discovery-progress-directory=", "-manifest=" + fixture.manifest, "-list"}},
		{"list", []string{"-list"}},
		{"explicit default suite", []string{"-suite=all"}},
		{"manifest", []string{"-manifest=" + fixture.manifest}},
		{"shard count", []string{"-discovery-shard-count=1"}},
		{"progress output", []string{"-discovery-progress-output=unused"}},
		{"verified reports", []string{"-verify-discovery-reports=unused"}},
		{"progress reader", []string{"-discovery-progress=unused"}},
		{"ledger writer", []string{"-write-assembly-ledger=unused"}},
		{"ledger status", []string{"-assembly-ledger-status=unused"}},
		{"require verified ledger", []string{"-require-verified-assembly-ledger"}},
		{"events", []string{"-discovery-events=unused"}},
		{"exact candidate", []string{"-discovery-exact-candidate=example.com/a@v1.0.0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := []string{
				"-repo-root=" + fixture.root, "-discovery-ledger=" + fixture.ledger,
				"-compare-assembly-ledger=" + fixture.stored,
				"-discovery-progress-directory=" + filepath.Join(t.TempDir(), "new"),
			}
			if test.args[0] == "-discovery-progress-directory=" {
				// Do not let the unrelated compare-requires-verify guard mask an
				// empty directory mode falling through to a successful list reader.
				args = []string{"-repo-root=" + fixture.root}
			}
			stdout, stderr, err := runVerifiedProgressCLI(ctx, fixture.root, append(args, test.args...)...)
			if err == nil || len(stdout) != 0 || !strings.Contains(string(stderr), "requires") {
				t.Fatalf("directory mode fell through or accepted another mode: %v stdout=%q stderr=%s", err, stdout, stderr)
			}
		})
	}
}

func TestDiscoveryProgressDirectoryPhysicalCaseAliasesRealCLI(t *testing.T) {
	for _, kind := range []string{"scan ledger", "assembly ledger", "repository"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newFrozenAggregateFixture(t)
			input, reason := fixture.ledger, "overlaps"
			if kind == "assembly ledger" {
				input = fixture.stored
			} else if kind == "repository" {
				renamed := filepath.Join(t.TempDir(), "repository")
				if err := os.Rename(fixture.root, renamed); err != nil {
					t.Fatal(err)
				}
				fixture.root, input, reason = renamed, renamed, "ignored _out"
			}
			alias := filepath.Join(filepath.Dir(input), strings.ToUpper(filepath.Base(input)))
			if alias == input {
				t.Fatal("fixture needs a genuinely different case spelling")
			}
			original, err := os.Stat(input)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := os.Stat(alias)
			if os.IsNotExist(err) {
				// A case-sensitive filesystem gets a real independent directory.
				// It must stay allowed: blanket case folding is not isolation.
				if err := os.Mkdir(alias, 0700); err != nil {
					t.Fatal(err)
				}
				observed, err = os.Stat(alias)
			}
			if err != nil {
				t.Fatal(err)
			}
			samePhysical := os.SameFile(original, observed)
			t.Logf("actual filesystem case alias: kind=%s samePhysical=%t", kind, samePhysical)
			output := filepath.Join(alias, "new-reports")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stdout, stderr, err := runVerifiedProgressCLI(ctx, fixture.root,
				"-repo-root="+fixture.root, "-discovery-ledger="+fixture.ledger,
				"-compare-assembly-ledger="+fixture.stored, "-discovery-progress-directory="+output)
			if samePhysical {
				if err == nil || len(stdout) != 0 || !strings.Contains(string(stderr), reason) {
					t.Fatalf("physical case alias bypassed isolation: %v stdout=%q stderr=%s", err, stdout, stderr)
				}
			} else if err != nil || len(stdout) == 0 {
				t.Fatalf("different case-sensitive directory was rejected: %v stdout=%q stderr=%s", err, stdout, stderr)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("case preflight wrote its output: %v", err)
			}
		})
	}
}

func copyFrozenGitRelay(t *testing.T, destination string) {
	t.Helper()
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, source)
	closeSource, closeOutput := source.Close(), output.Close()
	if copyErr != nil || closeSource != nil || closeOutput != nil {
		t.Fatalf("copy Git relay: %v %v %v", copyErr, closeSource, closeOutput)
	}
}
