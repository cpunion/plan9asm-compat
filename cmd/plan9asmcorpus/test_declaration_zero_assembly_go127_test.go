//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestTestDeclarationDependencyProducerZeroAssemblySibling(t *testing.T) {

	compilerEnv := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/zeroassembly", Version: "v1.0.0",
		AsmFiles: []string{"probe_386.s", "probe_amd64.s"},
	}
	sources := map[string]string{
		"go.mod":          "module example.invalid/zeroassembly\n\ngo 1.20\n",
		"probe.go":        "package zeroassembly\n",
		"probe_test.go":   "package zeroassembly\nimport \"example.invalid/zeroassembly/helper\"\nfunc probe(x helper.Float) helper.Float\n",
		"helper/float.go": "package helper\ntype Float = float32\n",
		"helper/asm.s":    "",
		"probe_amd64.s":   "#include \"textflag.h\"\nTEXT ·probe(SB),NOSPLIT,$0-12\nMOVSS x+0(FP),X0\nMOVSS X0,ret+8(FP)\nRET\n",
		"probe_386.s":     "#include \"textflag.h\"\nTEXT ·probe(SB),NOSPLIT,$0-8\nMOVSS x+0(FP),X0\nMOVSS X0,ret+4(FP)\nRET\n",
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
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", binary, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build owned translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{"darwin/amd64", "linux/386"}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: targets, CandidateTimeout: 3 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Success != 2 || len(matrix.FeatureConsumption) != 2 {
		t.Fatal("source-only zero-byte sibling changed real candidate LLVM object counts")
	}
	plan := matrix.OrdinarySelectionPlan
	if len(plan.TestedAsmFiles) != 2 || len(plan.TestDeclarationQueries) != 2 {
		t.Fatal("source-only sibling acquired an ordinary assembly scope or lost its actual typed query")
	}
	const zero = "helper/asm.s"
	for _, query := range plan.TestDeclarationQueries {
		if len(query.Dependency.Packages) != 2 {
			t.Fatal("actual root/helper source closure is incomplete")
		}
		helper := query.Dependency.Packages[1].Package
		if len(helper.SFiles) != 1 || helper.SFiles[0] != zero ||
			helper.SourceSHA256[zero] != discoveryFeatureBytesSHA256(nil) {
			t.Fatal("actual Go-selected empty SFile or its original byte identity disappeared")
		}
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
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"original": func(*discoveryCorpusResult) {},
		"consumer-only missing zero role": func(r *discoveryCorpusResult) {
			r.FeatureConsumption[0].TestDependencies.Packages[1].Package.SFiles = nil
		},
		"paired role and byte deletion": func(r *discoveryCorpusResult) {
			mutateZeroAssemblyDependencies(r, func(d *gotoolprofile.TestDependencyProof) {
				d.Packages[1].Package.SFiles = nil
				delete(d.Packages[1].Package.SourceSHA256, zero)
			})
		},
		"paired role and header deletion": func(r *discoveryCorpusResult) {
			mutateZeroAssemblyDependencies(r, func(d *gotoolprofile.TestDependencyProof) {
				d.Packages[1].Package.SFiles = nil
				delete(d.Packages[1].Package.SourceSHA256, zero)
			})
			var retained []ordinarySelectionSource
			for _, source := range r.OrdinarySelectionPlan.TestDeclarationSources {
				if source.File != zero {
					retained = append(retained, source)
				}
			}
			r.OrdinarySelectionPlan.TestDeclarationSources = retained
		},
		"same hash without original member": func(r *discoveryCorpusResult) {
			for index := range r.OrdinarySelectionPlan.TestDeclarationDirectories {
				dir := &r.OrdinarySelectionPlan.TestDeclarationDirectories[index]
				if dir.Directory == "helper" {
					var retained []ordinarySelectionEntry
					for _, entry := range dir.Entries {
						if entry.Name != "asm.s" {
							retained = append(retained, entry)
						}
					}
					dir.Entries = retained
				}
			}
		},
		"fabricated empty sibling object count": func(r *discoveryCorpusResult) { r.Translations++ },
	} {
		t.Run(name, func(t *testing.T) {
			var replay discoveryCorpusResult
			if err := json.Unmarshal(encoded, &replay); err != nil {
				t.Fatal(err)
			}
			replay.featureInventory = inventory
			mutate(&replay)
			err := validateOrdinaryProfileResult(replay, targets, plan.GoVersion)
			if name == "original" && err != nil {
				t.Fatal(err)
			}
			if name != "original" && err == nil {
				t.Fatal("strict reader accepted changed or omitted source-only empty sibling evidence")
			}
		})
	}
	if err := os.WriteFile(filepath.Join(download.Dir, zero), []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryTestDependencySources(plan, download.Dir, download.Zip); err == nil {
		t.Fatal("actual original zero source became whitespace after loading without failing")
	}
}
