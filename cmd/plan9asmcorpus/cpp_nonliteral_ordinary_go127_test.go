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

func TestOrdinaryCPPFormalIncludeOperandsDefaultTargetsAndReaders(t *testing.T) {
	checkOrdinaryCPPFormalIncludes(t,
		"darwin/amd64,darwin/arm64,linux/386,linux/amd64,linux/arm,linux/arm64,windows/386,windows/amd64,windows/arm64,js/wasm,wasip1/wasm", false)
}

func TestOrdinaryCPPFormalGeneratedHeaderUsesActualNativeProducer(t *testing.T) {
	// This single-target first-party scope independently exercises query-only
	// header observations and the missing-inventory negative. It is not
	// full-default coverage; profiles are bounded per actual target.
	checkOrdinaryCPPFormalIncludes(t, "linux/amd64", true)
}

func checkOrdinaryCPPFormalIncludes(t *testing.T, targetList string, generatedHeader bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	repo, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	if stdout, stderr, err := runDiscoveryMachineCommand(ctx, filepath.Join(repo, "cmd/plan9asmll"),
		os.Environ(), "go", "build", "-p=2", "-o", translator, "."); err != nil {
		t.Fatalf("actual translator build: %v\n%s\n%s", err, stdout, stderr)
	} else if len(stderr) != 0 {
		t.Logf("actual translator build notices:\n%s", stderr)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	candidate := discoveryCandidate{
		Module: "example.invalid/ordinary-formal-includes", Version: "v1.0.0", AsmFiles: []string{"probe.s"},
	}
	sources := map[string]string{
		"go.mod":   "module example.invalid/ordinary-formal-includes\n\ngo 1.20\n",
		"probe.go": "package fixture\nfunc Probe()\n",
		"cpu.s":    "// Original nonempty selected sibling, not a discovered file.\n",
		"probe.s": "#include \"macros.h\"\n" +
			"INCLUDE(\"formal.h\")\nAPPLY(\"nested.h\")\nALIAS(\"alias.h\")\n" +
			"INCLUDE(\"../../src/runtime/go_tls.h\")\n" +
			"TEXT ·Probe(SB),4,$0-0\nRET\n" +
			"DATA ·unused(SB)/8,$\"nofile.h\"\nGLOBL ·unused(SB),$8\n",
		"macros.h": "#define INCLUDE(file) \\\n#include file \\\n\n" +
			"#define APPLY(file) INCLUDE(file)\n#define ALIAS INCLUDE\n",
		"formal.h": "GLOBL ·formalMarker(SB),$8\n",
		"nested.h": "GLOBL ·nestedMarker(SB),$8\n",
		"alias.h":  "GLOBL ·aliasMarker(SB),$8\n",
	}
	if generatedHeader {
		sources["probe.go"] = "package fixture\ntype Record struct { Value uint64 }\nfunc Probe()\n"
		sources["probe.s"] = strings.Replace(sources["probe.s"], "#include \"macros.h\"\n",
			"#include \"macros.h\"\nINCLUDE(\"go_asm.h\")\nGLOBL ·recordMarker(SB),$Record__size\n", 1)
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	targets, err := parseDiscoveryTargets(targetList)
	if err != nil || len(targets) != len(strings.Split(targetList, ",")) {
		t.Fatalf("original target denominator: %v %v", targets, err)
	}
	for _, target := range targets {
		goos, goarch, _ := strings.Cut(target, "/")
		env := replaceEnv(os.Environ(), map[string]string{"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"})
		stdout, stderr, err := runDiscoveryMachineCommand(ctx, download.Dir, env,
			"go", "list", "-p=2", "-mod=readonly", "-export", "-json", ".")
		if err != nil || len(stderr) != 0 {
			t.Fatalf("actual original %s export: %v\n%s\n%s", target, err, stdout, stderr)
		}
		var selected struct {
			GoFiles, SFiles []string
			Export          string
		}
		if err := json.Unmarshal(stdout, &selected); err != nil ||
			!equalDiscoveryStrings(selected.GoFiles, []string{"probe.go"}) ||
			!equalDiscoveryStrings(selected.SFiles, []string{"cpu.s", "probe.s"}) || selected.Export == "" {
			t.Fatalf("actual original selection %s: %+v %v", target, selected, err)
		}
		digest, err := discoveryFeatureFileSHA256(selected.Export)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("FORMAL_ORDINARY_ACTUAL_GO %s export_sha=%s source_sha=%s", target,
			digest, discoveryFeatureBytesSHA256([]byte(sources["probe.s"])))
	}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: repo, Translator: translator, LLC: llc, Targets: targets, CandidateTimeout: 5 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("actual original formal includes failed ordinary producer: %v", err)
	}
	if matrix.Success < len(targets) || matrix.NotApplicable != 0 || len(matrix.FeatureConsumption) != len(configs) {
		t.Fatalf("ordinary scopes missing: objects=%d N/A=%d consumers=%d configs=%d",
			matrix.Success, matrix.NotApplicable, len(matrix.FeatureConsumption), len(configs))
	}
	inventory, refs := fixtureOrdinaryMatrixFeatureInventory(t, matrix)
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: discoveryConfigurationAsmFiles(configs),
		BuildConfigurations: configs, Translations: matrix.Success, OrdinarySelectionPlan: matrix.OrdinarySelectionPlan,
		FeatureProfiles: refs, FeatureConsumption: matrix.FeatureConsumption, featureInventory: inventory,
	}
	if err := validateOrdinaryProfileResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatal(err)
	}
	if generatedHeader {
		assertCPPHeaderPlanningQueryInventoryRequired(t, result, inventory, targets)
	}
	checkSelectedSiblingReportReaders(t, candidate, result, targets, inventory)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	originalBytes := 0
	for _, source := range matrix.OrdinarySelectionPlan.CPPInputs.Sources {
		originalBytes += len(*source.Original)
	}
	t.Logf("FORMAL_ORDINARY_CLOSED objects=%d configs=%d source_bytes=%d result_bytes=%d",
		matrix.Success, len(configs), originalBytes, len(encoded))
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"delete_candidate_and_original": func(copy *discoveryCorpusResult) {
			delete(copy.OrdinarySelectionPlan.CPPInputs.Sources, "module/formal.h")
			for index := range copy.OrdinarySelectionPlan.CPPInputs.Units {
				for key, target := range copy.OrdinarySelectionPlan.CPPInputs.Units[index].Includes {
					if target == "module/formal.h" {
						delete(copy.OrdinarySelectionPlan.CPPInputs.Units[index].Includes, key)
					}
				}
			}
		},
		"delete_original_protocol_and_graph": func(copy *discoveryCorpusResult) {
			copy.OrdinarySelectionPlan.CPPSourceProtocol = ""
			copy.OrdinarySelectionPlan.CPPInputs = nil
		},
		"paired_output_input_deletion": func(copy *discoveryCorpusResult) {
			for _, proof := range copy.FeatureConsumption {
				for index := range proof.CPP {
					delete(proof.CPP[index].Inputs, "module/formal.h")
					proof.CPP[index].ExpandedSHA256 = strings.Repeat("a", 64)
				}
			}
		},
		"paired_active_receipt_deletion": func(copy *discoveryCorpusResult) {
			for _, proof := range copy.FeatureConsumption {
				proof.CPPIncludeSearchMisses = nil
				for index := range proof.CPP {
					proof.CPP[index].ExpandedSearchMisses = nil
				}
			}
		},
		"paired_active_receipt_downgrade": func(copy *discoveryCorpusResult) {
			for _, proof := range copy.FeatureConsumption {
				for index := range proof.CPPIncludeSearchMisses {
					proof.CPPIncludeSearchMisses[index].Protocol = gotoolprofile.CPPPackageSearchMissProtocol
					proof.CPPIncludeSearchMisses[index].Source = "module/macros.h"
				}
				for index := range proof.CPP {
					for receipt := range proof.CPP[index].ExpandedSearchMisses {
						proof.CPP[index].ExpandedSearchMisses[receipt].Protocol = gotoolprofile.CPPPackageSearchMissProtocol
						proof.CPP[index].ExpandedSearchMisses[receipt].Source = "module/macros.h"
					}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var copy discoveryCorpusResult
			if err := json.Unmarshal(encoded, &copy); err != nil {
				t.Fatal(err)
			}
			copy.featureInventory = inventory
			mutate(&copy)
			if err := validateOrdinaryProfileResult(copy, targets, result.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatal("deleted, downgraded or forged formal-include result was accepted")
			}
		})
	}
}
