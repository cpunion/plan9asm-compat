//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrdinaryMixedPackagesProducerKeepsEligibleObjects(t *testing.T) {
	compilerEnv := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/mixed-packages", Version: "v1.0.0",
		AsmFiles: []string{"bad/probe_amd64.s", "good/probe_amd64.s"},
	}
	sources := map[string]string{
		"go.mod":             "module example.invalid/mixed-packages\n\ngo 1.20\n",
		"bad/probe.go":       "package bad\nfunc Probe()\n",
		"bad/probe_test.go":  "package bad_x\n",
		"bad/probe_amd64.s":  "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n",
		"good/probe.go":      "package good\nfunc Probe() uint64\n",
		"good/probe_test.go": "package good_test\n",
		"good/probe_amd64.s": "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-8\nMOVQ $7,ret+0(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", translator, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build actual translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal("required LLVM 22 llc: ", err)
	}
	targets := []string{"darwin/amd64", "linux/amd64", "windows/amd64"}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: translator, LLC: llc,
		Targets: targets, CandidateTimeout: 2 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("original Go package conflict lacks a bound source rejection: %v", err)
	}
	if matrix.Success != len(targets) || matrix.Failed != 0 || len(configs) != len(targets) ||
		len(matrix.SourceNotApplicableItems) != len(targets) {
		t.Fatalf("source refusal erased valid sibling objects or manufactured success: success=%d failed=%d configs=%d refusals=%d",
			matrix.Success, matrix.Failed, len(configs), len(matrix.SourceNotApplicableItems))
	}
	for _, item := range matrix.SourceNotApplicableItems {
		if item.Kind != "go_mixed_package_clauses_rejected_package_target" ||
			!equalDiscoveryStrings(item.AsmFiles, []string{"bad/probe_amd64.s"}) ||
			!strings.Contains(item.Reason, "found packages bad (probe.go) and bad_x (probe_test.go)") {
			t.Fatalf("unbound or foreign package refusal: %+v", item)
		}
	}
	for _, config := range configs {
		if !equalDiscoveryStrings(config.AsmFiles, []string{"good/probe_amd64.s"}) {
			t.Fatal("mixed-package refusal crossed into the valid external-test package")
		}
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: discoveryConfigurationAsmFiles(configs),
		BuildConfigurations: configs, Translations: matrix.Success,
		OrdinarySelectionPlan: matrix.OrdinarySelectionPlan, FeatureProfiles: refs,
		FeatureConsumption:       matrix.FeatureConsumption,
		SourceNotApplicableItems: matrix.SourceNotApplicableItems, featureInventory: inventory,
	}
	if err := validateOrdinaryProfileResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatalf("original source conflict and actual LLVM object proof do not replay together: %v", err)
	}
	if err := validateOrdinarySelectionResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
		t.Fatal("legacy reader accepted a current typed mixed-package proof")
	}
	compact := result
	compact.sourceDiagnosticsCompacted = true
	compact.SourceNotApplicableItems = append([]discoverySourceNotApplicableItem(nil), result.SourceNotApplicableItems...)
	for index := range compact.SourceNotApplicableItems {
		compact.SourceNotApplicableItems[index].Reason = discoverySourceSkipReason(compact.SourceNotApplicableItems[index].Kind)
	}
	if err := validateOrdinaryProfileResult(compact, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatalf("compact progress/ledger lost typed loader evidence: %v", err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"missing proof":       func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.MixedPackageRejections = nil },
		"missing source item": func(r *discoveryCorpusResult) { r.SourceNotApplicableItems = r.SourceNotApplicableItems[1:] },
		"paired deletion": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections = r.OrdinarySelectionPlan.MixedPackageRejections[1:]
			r.SourceNotApplicableItems = r.SourceNotApplicableItems[1:]
		},
		"duplicate proof": func(r *discoveryCorpusResult) {
			p := r.OrdinarySelectionPlan
			p.MixedPackageRejections = append(p.MixedPackageRejections, p.MixedPackageRejections[0])
		},
		"missing test roles":    func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.MixedPackageRejections[0].TestGoFiles = nil },
		"missing invalid roles": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.MixedPackageRejections[0].InvalidGoFiles = nil },
		"foreign package": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].Package.PackagePath = "other.invalid/probe"
		},
		"foreign version": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].Package.SourceVersion = "v1.0.1"
		},
		"foreign profile": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].ProfileID = strings.Repeat("a", 64)
		},
		"foreign directory": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.MixedPackageRejections[0].Directory = "good" },
		"foreign selected filename": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].ConflictFiles[1] = "unselected.go"
		},
		"foreign loader rules": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].Rules.SourceSHA256["src/cmd/go/internal/modindex/read.go"] = strings.Repeat("a", 64)
		},
		"missing raw receipt": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].OriginalDiagnosticSHA256 = ""
		},
		"mixed stderr": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].Stderr += "other.go:3: undefined: x\n"
		},
		"nonempty stdout": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].Stdout = "partial export"
		},
		"signal exit": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.MixedPackageRejections[0].ExitCode = -1 },
		"fake position": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].LoaderError.Pos = "probe.go:1"
		},
		"foreign import stack": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].LoaderError.ImportStack = []string{"other.invalid/probe"}
		},
		"ordinary relabel": func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems[0].Kind = discoverySourceNotApplicableGoBuild
		},
		"cross-sibling exclusion": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.MixedPackageRejections[0].AsmFiles = append(r.OrdinarySelectionPlan.MixedPackageRejections[0].AsmFiles, "good/probe_amd64.s")
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			mutate(&changed)
			if validateOrdinaryProfileResult(changed, targets, matrix.OrdinarySelectionPlan.GoVersion) == nil {
				t.Fatal("incomplete, foreign or relabeled loader proof accepted")
			}
		})
	}
	encoded, err := json.Marshal(matrix.OrdinarySelectionPlan)
	if err != nil || !strings.Contains(string(encoded), "mixed_package_rejections") {
		t.Fatal("portable report omitted the independently replayable package-clause proof: ", err)
	}
	if strings.Contains(string(encoded), download.Dir) || strings.Contains(string(encoded), "/Users/") {
		t.Fatal("portable plan retained a private physical download path")
	}
}
