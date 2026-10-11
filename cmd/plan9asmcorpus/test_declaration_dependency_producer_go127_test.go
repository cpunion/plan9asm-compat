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

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestTestDeclarationDependencyProducerOriginalPureGoClosure(t *testing.T) {

	compilerEnv := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/testdecl", Version: "v1.0.0",
		AsmFiles: []string{"call_386.s", "call_amd64.s", "internal/scalar/value_386.s", "internal/scalar/value_amd64.s", "probe_386.s", "probe_amd64.s", "tail_386.s", "tail_amd64.s"},
	}
	sources := map[string]string{
		"go.mod":                        "module example.invalid/testdecl\n\ngo 1.20\n",
		"probe.go":                      "package testdecl\n",
		"probe_test.go":                 "package testdecl\nimport \"example.invalid/testdecl/internal/layout\"\nfunc probe(x layout.Float) layout.Float\nfunc tail(x layout.Float) layout.Float\nfunc call(x layout.Float) layout.Float\n",
		"internal/layout/value.go":      "package layout\nimport \"example.invalid/testdecl/internal/scalar\"\ntype Float = scalar.Float\n",
		"internal/scalar/value.go":      "package scalar\ntype Float = float32\nfunc marker()\n",
		"internal/scalar/value_amd64.s": "#include \"textflag.h\"\nTEXT ·marker(SB),NOSPLIT,$0-0\nRET\n",
		"internal/scalar/value_386.s":   "#include \"textflag.h\"\nTEXT ·marker(SB),NOSPLIT,$0-0\nRET\n",
		"probe_amd64.s":                 "#include \"textflag.h\"\nTEXT ·probe(SB),NOSPLIT,$0-12\nMOVSS x+0(FP),X0\nMOVSS X0,ret+8(FP)\nRET\n",
		"tail_amd64.s":                  "#include \"textflag.h\"\nTEXT ·tail(SB),NOSPLIT,$0-12\nJMP ·probe(SB)\n",
		"call_amd64.s":                  "#include \"textflag.h\"\nTEXT ·call(SB),NOSPLIT,$16-12\nMOVSS x+0(FP),X0\nMOVSS X0,0(SP)\nCALL ·probe(SB)\nMOVSS 8(SP),X0\nMOVSS X0,ret+8(FP)\nRET\n",
		"probe_386.s":                   "#include \"textflag.h\"\nTEXT ·probe(SB),NOSPLIT,$0-8\nMOVSS x+0(FP),X0\nMOVSS X0,ret+4(FP)\nRET\n",
		"tail_386.s":                    "#include \"textflag.h\"\nTEXT ·tail(SB),NOSPLIT,$0-8\nJMP ·probe(SB)\n",
		"call_386.s":                    "#include \"textflag.h\"\nTEXT ·call(SB),NOSPLIT,$8-8\nMOVSS x+0(FP),X0\nMOVSS X0,0(SP)\nCALL ·probe(SB)\nMOVSS 4(SP),X0\nMOVSS X0,ret+4(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, download, sources["go.mod"])
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "plan9asmll")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", binary, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build owned translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{"darwin/amd64", "linux/amd64", "windows/amd64", "linux/386", "windows/386"}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: targets,
		CandidateTimeout: 3 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("original same-module pure-Go test import closure: %v", err)
	}
	if matrix.Success != 20 || len(matrix.FeatureConsumption) != 10 {
		t.Fatalf("test-declaration metadata is not an object count: %#v", matrix)
	}
	plan := matrix.OrdinarySelectionPlan
	if len(plan.GeneratedGoSources) != 0 || len(plan.GeneratedHeaders) != 0 || len(plan.Directories) != 3 ||
		len(plan.TestDeclarationQueries) != 5 || len(plan.TestDeclarationQueries[0].Dependency.Packages) != 3 {
		t.Fatal("test dependencies changed ordinary/header selection or lost the transitive source-only closure")
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles,
		BuildConfigurations: configs, Translations: matrix.Success, OrdinarySelectionPlan: plan,
		FeatureProfiles: refs, FeatureConsumption: matrix.FeatureConsumption, featureInventory: inventory,
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	replay := func(t *testing.T, mutate func(*discoveryCorpusResult), rejected bool) {
		t.Helper()
		var current discoveryCorpusResult
		if err := json.Unmarshal(encoded, &current); err != nil {
			t.Fatal(err)
		}
		current.featureInventory = inventory
		mutate(&current)
		err := validateOrdinaryProfileResult(current, targets, plan.GoVersion)
		if rejected && err == nil {
			t.Fatal("reader accepted changed/truncated/unconsumed test-declaration source closure")
		}
		if !rejected && err != nil {
			t.Fatalf("original source-only closure JSON replay: %v", err)
		}
	}
	replay(t, func(*discoveryCorpusResult) {}, false)
	mutations := map[string]func(*discoveryCorpusResult){
		"missing current plan marker":     func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.TestDependencySourceProtocol = "" },
		"missing current consumer marker": func(r *discoveryCorpusResult) { r.FeatureConsumption[0].TestDependencySourceProtocol = "" },
		"delete both closure fields": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.TestDeclarationQueries = nil
			r.OrdinarySelectionPlan.TestDeclarationSources = nil
			r.OrdinarySelectionPlan.TestDeclarationDirectories = nil
			r.FeatureConsumption[0].TestDependencies = nil
		},
		"missing query": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.TestDeclarationQueries = nil },
		"duplicate query": func(r *discoveryCorpusResult) {
			p := r.OrdinarySelectionPlan
			p.TestDeclarationQueries = append(p.TestDeclarationQueries, p.TestDeclarationQueries[0])
		},
		"query no LLVM is not pass": func(r *discoveryCorpusResult) { r.FeatureConsumption[0].Outputs = nil },
		"missing preload source":    func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.TestDeclarationSources = nil },
		"missing source directory":  func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.TestDeclarationDirectories = nil },
		"changed source bytes": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.TestDeclarationSources[0].SHA256 = strings.Repeat("a", 64)
		},
		"changed source header": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.TestDeclarationSources[0].Header += "import \"missing.invalid\"\n"
		},
		"missing transitive package": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Packages = r.FeatureConsumption[0].TestDependencies.Packages[:2]
		},
		"changed exact version": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Packages[1].Package.ModuleVersion = "v1.0.1"
		},
		"different source role": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Packages[1].Package.SourceRole = "stdlib"
		},
		"different variant identity": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Packages[0].VariantID += "_test"
		},
		"changed ImportMap": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Packages[0].ImportMap = map[string]string{}
		},
		"foreign package": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Packages[1].Package.PackagePath = "foreign.invalid/scalar"
		},
		"different profile": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.TestDeclarationQueries[0].ProfileID = strings.Repeat("f", 64)
		},
		"different target": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.TestDeclarationQueries[0].Target = "windows/amd64"
		},
		"different tags": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.TestDeclarationQueries[0].BuildTags = []string{"other"}
		},
		"query falsely has output": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Query.Selection.Outputs = r.FeatureConsumption[0].Outputs
		},
		"changed normalized source": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Query.Selection.CPP[0].TypedExpandedSHA256 = strings.Repeat("c", 64)
		},
		"unused symbol": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Query.Requests[0].Symbol += "Unused"
		},
		"wrong entry callee": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Query.Requests[0].Callee = true
		},
		"changed source ABI selector": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Query.Requests[0].ABIInternal = true
		},
		"test source faked as ordinary": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.Sources = append(r.OrdinarySelectionPlan.Sources, r.OrdinarySelectionPlan.TestDeclarationSources[0])
		},
		"query cannot outlive execution": func(r *discoveryCorpusResult) { r.BuildConfigurations = nil },
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) { replay(t, mutation, true) })
	}
	// Mutate producer and consumer together too. Agreement alone must not
	// authorize a truncated closure or a relabeled source/profile contract.
	consistentMutations := map[string]func(*gotoolprofile.TestDependencyProof){
		"truncate transitive closure": func(d *gotoolprofile.TestDependencyProof) { d.Packages = d.Packages[:2] },
		"change module version":       func(d *gotoolprofile.TestDependencyProof) { d.Packages[1].Package.ModuleVersion = "v1.0.1" },
		"change source role":          func(d *gotoolprofile.TestDependencyProof) { d.Packages[1].Package.SourceRole = "stdlib" },
		"change source SHA": func(d *gotoolprofile.TestDependencyProof) {
			for file := range d.Packages[1].Package.SourceSHA256 {
				d.Packages[1].Package.SourceSHA256[file] = strings.Repeat("e", 64)
			}
		},
		"remove import edge": func(d *gotoolprofile.TestDependencyProof) { d.Packages[0].ImportMap = map[string]string{} },
		"wrong ABI selector": func(d *gotoolprofile.TestDependencyProof) { d.Query.Requests[0].ABIInternal = true },
		"callee disguised as entry": func(d *gotoolprofile.TestDependencyProof) {
			for index := range d.Query.Requests {
				d.Query.Requests[index].Callee = false
			}
		},
		"query invents ordinary type consumption": func(d *gotoolprofile.TestDependencyProof) {
			d.Query.Selection.CPP[0].Signatures = []gotoolprofile.SignatureSource{{Symbol: "invented"}}
		},
		"query changes normalized source": func(d *gotoolprofile.TestDependencyProof) {
			d.Query.Selection.CPP[0].TypedExpandedSHA256 = strings.Repeat("c", 64)
		},
		"query claims unused symbol":         func(d *gotoolprofile.TestDependencyProof) { d.Query.Requests[0].Symbol += "Unused" },
		"different actual synthetic package": func(d *gotoolprofile.TestDependencyProof) { d.Packages[0].VariantID += "_test" },
		"query-only output is not translation": func(d *gotoolprofile.TestDependencyProof) {
			d.Query.Selection.Outputs = []gotoolprofile.OutputProof{{File: "probe_amd64.s", Part: "fake.ll", IR: strings.Repeat("a", 64)}}
		},
	}
	for name, mutation := range consistentMutations {
		t.Run("consistent "+name, func(t *testing.T) {
			replay(t, func(r *discoveryCorpusResult) {
				mutation(r.OrdinarySelectionPlan.TestDeclarationQueries[0].Dependency)
				mutation(r.FeatureConsumption[0].TestDependencies)
			}, true)
		})
	}
	if err := verifyDiscoveryTestDependencySources(plan, download.Dir, download.Zip); err != nil {
		t.Fatal(err)
	}
	t.Run("actual extra source after preload", func(t *testing.T) {
		file := filepath.Join(download.Dir, "internal", "layout", "late.go")
		if err := os.WriteFile(file, []byte("package layout\n"), 0600); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Remove(file); err != nil {
				t.Error(err)
			}
		}()
		if err := verifyDiscoveryTestDependencySources(plan, download.Dir, download.Zip); err == nil {
			t.Fatal("new unselected directory member bypassed source-only preload guard")
		}
	})
	t.Run("actual source replaced after preload", func(t *testing.T) {
		file := filepath.Join(download.Dir, "internal", "layout", "value.go")
		before, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(file, before, 0600); err != nil {
				t.Error(err)
			}
		}()
		if err := os.WriteFile(file, []byte("package layout\ntype Float = float64\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyDiscoveryTestDependencySources(plan, download.Dir, download.Zip); err == nil {
			t.Fatal("changed dependency bytes bypassed original ZIP/preload guard")
		}
	})
}
