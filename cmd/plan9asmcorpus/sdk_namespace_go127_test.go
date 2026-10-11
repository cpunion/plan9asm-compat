//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A module can own a standard import prefix. Stock Go rejects this exact
// duplicate before compiler selection, with a positionless loader error.
// The source refusal is not an assembly object or instruction pass.
func TestOrdinarySDKNamespaceCollisionProducerSourceNA(t *testing.T) {
	compilerEnv := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/sdk-namespace", Version: "v1.0.0",
		AsmFiles: []string{"compile/internal/ssa/probe.s", "plan9asm-fixture/probe.s"},
	}
	sources := map[string]string{
		"go.mod":                        "module cmd\n\ngo 1.20\n",
		"compile/internal/ssa/probe.go": "package ssa\nfunc Probe()\n",
		"compile/internal/ssa/probe.s":  "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n",
		"plan9asm-fixture/probe.go":     "package fixture\nfunc Probe()\n",
		"plan9asm-fixture/probe.s":      "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	env := replaceEnv(os.Environ(), map[string]string{
		"GOWORK": "off", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0",
		"GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "", "GOEXPERIMENT": "",
	})
	stdout, stderr, failure := runDiscoveryMachineCommand(ctx, download.Dir, env,
		"go", "list", "-export", "-mod=mod", "cmd/compile/internal/ssa")
	var exit *exec.ExitError
	if !errors.As(failure, &exit) || exit.ExitCode() != 1 || len(stdout) != 0 ||
		!strings.HasPrefix(string(stderr), "ambiguous import: found package cmd/compile/internal/ssa in multiple modules:\n") ||
		!strings.Contains(string(stderr), filepath.Join(download.Dir, "compile", "internal", "ssa")) ||
		!strings.Contains(string(stderr), filepath.Join(runtime.GOROOT(), "src", "cmd", "compile", "internal", "ssa")) {
		t.Fatalf("original first-party module did not expose the stock SDK collision: error=%v stdout=%s stderr=%s", failure, stdout, stderr)
	}
	t.Logf("actual stock Go namespace collision (not a concrete file:line compiler diagnostic):\n%s", stderr)
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
	targets := []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: translator, LLC: llc,
		Targets: targets, CandidateTimeout: 2 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("exact original module/SDK namespace collision lacks a typed source rejection: %v", err)
	}
	if matrix.Success != len(targets) || matrix.Failed != 0 || len(configs) != len(targets) || len(matrix.SourceNotApplicableItems) != len(targets) {
		t.Fatalf("namespace refusal manufactured objects or lost its source scope: success=%d failed=%d configs=%d items=%+v",
			matrix.Success, matrix.Failed, len(configs), matrix.SourceNotApplicableItems)
	}
	for _, config := range configs {
		if !equalDiscoveryStrings(config.AsmFiles, []string{"plan9asm-fixture/probe.s"}) {
			t.Fatal("SDK collision consumed valid sibling assembly")
		}
	}
	for _, item := range matrix.SourceNotApplicableItems {
		if item.Kind != discoverySourceNotApplicableSDKNamespace || !equalDiscoveryStrings(item.AsmFiles, []string{"compile/internal/ssa/probe.s"}) {
			t.Fatalf("unbound SDK collision: %+v", item)
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
		FeatureConsumption: matrix.FeatureConsumption, SourceNotApplicableItems: matrix.SourceNotApplicableItems, featureInventory: inventory,
	}
	if err := validateOrdinaryProfileResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatal("independent namespace/source/object reader: ", err)
	}
	if err := validateOrdinarySelectionResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
		t.Fatal("legacy reader accepted current SDK namespace proof")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	// Retained module-query bytes, not a pattern-valid opaque hash, are needed
	// by the independent reader. This assertion exposes the first draft gap.
	if !strings.Contains(string(encoded), "portable_module_stdout") {
		t.Fatal("module-query hash has no independently replayable retained stdout")
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"missing proof":       func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.SDKNamespaceRejections = nil },
		"missing source item": func(r *discoveryCorpusResult) { r.SourceNotApplicableItems = r.SourceNotApplicableItems[1:] },
		"duplicate proof": func(r *discoveryCorpusResult) {
			p := r.OrdinarySelectionPlan
			p.SDKNamespaceRejections = append(p.SDKNamespaceRejections, p.SDKNamespaceRejections[0])
		},
		"metadata hash": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].ModuleStdoutSHA256 = strings.Repeat("a", 64)
		},
		"diagnostic hash": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].StderrSHA256 = strings.Repeat("a", 64)
		},
		"malformed retained module": func(r *discoveryCorpusResult) {
			p := &r.OrdinarySelectionPlan.SDKNamespaceRejections[0]
			p.ModuleStdout = "{invalid"
			p.ModuleStdoutSHA256 = discoveryFeatureBytesSHA256([]byte(p.ModuleStdout))
		},
		"trailing retained module": func(r *discoveryCorpusResult) {
			p := &r.OrdinarySelectionPlan.SDKNamespaceRejections[0]
			p.ModuleStdout += "{}"
			p.ModuleStdoutSHA256 = discoveryFeatureBytesSHA256([]byte(p.ModuleStdout))
		},
		"coherent foreign module version": func(r *discoveryCorpusResult) {
			p := &r.OrdinarySelectionPlan.SDKNamespaceRejections[0]
			p.ModuleStdout = strings.ReplaceAll(p.ModuleStdout, "v1.0.0", "v1.0.1")
			p.ModuleStdoutSHA256 = discoveryFeatureBytesSHA256([]byte(p.ModuleStdout))
		},
		"trailing infrastructure": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].Stderr += "go: proxy.golang.org: connection refused\n"
		},
		"partial stdout": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].Stdout = "partial export"
		},
		"foreign package": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].PackagePath = "cmd/foreign"
		},
		"foreign SDK root": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].SDKDirectory.Directory = "src/cmd/foreign"
		},
		"foreign version": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.Version = "v1.0.1" },
		"foreign argv": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].Invocation = []string{"list", "-e", "cmd/compile/internal/ssa"}
		},
		"foreign rules": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].Rules.SourceSHA256["src/cmd/go/internal/modload/import.go"] = strings.Repeat("a", 64)
		},
		"sibling attribution": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.SDKNamespaceRejections[0].AsmFiles = []string{"plan9asm-fixture/probe.s"}
		},
		"ordinary relabel": func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems[0].Kind = discoverySourceNotApplicableGoBuild
		},
		"signal exit": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.SDKNamespaceRejections[0].ExitCode = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			mutate(&changed)
			if validateOrdinaryProfileResult(changed, targets, matrix.OrdinarySelectionPlan.GoVersion) == nil {
				t.Fatal("incomplete or foreign collision proof accepted")
			}
		})
	}
	compact := result
	compact.sourceDiagnosticsCompacted = true
	compact.SourceNotApplicableItems = append([]discoverySourceNotApplicableItem(nil), result.SourceNotApplicableItems...)
	for i := range compact.SourceNotApplicableItems {
		compact.SourceNotApplicableItems[i].Reason = discoverySourceSkipReason(compact.SourceNotApplicableItems[i].Kind)
	}
	if err := validateOrdinaryProfileResult(compact, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatal("compact proof lost collision evidence: ", err)
	}
	if strings.Contains(string(encoded), download.Dir) || strings.Contains(string(encoded), runtime.GOROOT()) {
		t.Fatal("portable proof retained a private physical root")
	}
}
