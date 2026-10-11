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

	"golang.org/x/mod/sumdb/dirhash"
)

// This first-party module runs through the original ordinary producer, not a
// reconstructed CPP-only source. Its file proxy is not external authentication.
func TestOrdinaryCPPDirectiveMacrosOriginalDefaultTargetsAndReaders(t *testing.T) {
	compilerEnvironment := os.Environ()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	if output, _, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "cmd", "plan9asmll"),
		compilerEnvironment, "go", "build", "-p=2", "-o", translator, "."); err != nil {
		t.Fatalf("build actual translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}

	candidate := discoveryCandidate{
		Module: "example.invalid/ordinary-directive-macros", Version: "v1.0.0",
		AsmFiles: []string{"probe.s"},
	}
	sources := map[string]string{
		"go.mod":   "module example.invalid/ordinary-directive-macros\n\ngo 1.20\n",
		"probe.go": "package fixture\nfunc Probe()\n",
		"cpu.s":    "// Original nonempty selected assembly sibling.\n",
		"probe.s": "#include \"macros.h\"\n" +
			"TEXT ·Probe(SB),4,$0-0\nRET\n" +
			"OBJECT_ALIAS\nAPPLY(GOARCH_amd64)\nINCLUDE_CHOICE\nINCLUDE_TOOL\n",
		"macros.h": "#define OBJECT \\\n" +
			"#ifdef GOARCH_arm64 \\\n" +
			"GLOBL ·armMarker(SB),$8 \\\n" +
			"#endif \\\n\n" +
			"#define OBJECT_ALIAS OBJECT\n" +
			"#define SELECT(P) \\\n" +
			"#ifdef P \\\n" +
			"GLOBL ·amdMarker(SB),$8 \\\n" +
			"#endif \\\n\n" +
			"#define APPLY(P) SELECT(P)\n" +
			"#define INCLUDE_CHOICE \\\n" +
			"#include \"choice.h\" \\\n\n" +
			"#define INCLUDE_TOOL \\\n#include \"../../src/runtime/go_tls.h\" \\\n\n",
		"choice.h": "GLOBL ·includeMarker(SB),$8\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	targets, err := parseDiscoveryTargets("darwin/amd64,darwin/arm64,linux/386,linux/amd64,linux/arm,linux/arm64,windows/386,windows/amd64,windows/arm64,js/wasm,wasip1/wasm")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 11 {
		t.Fatalf("original complete target denominator changed: %v", targets)
	}
	archiveSum, err := dirhash.HashZip(download.Zip, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		goos, goarch, _ := strings.Cut(target, "/")
		env := replaceEnv(os.Environ(), map[string]string{
			"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0",
		})
		output, stderr, err := runDiscoveryMachineCommand(ctx, download.Dir, env,
			"go", "list", "-p=2", "-mod=readonly", "-export", "-json", ".")
		if err != nil || len(stderr) != 0 {
			t.Fatalf("original %s selection/export: %v\n%s\n%s", target, err, output, stderr)
		}
		var selected struct {
			GoFiles []string
			SFiles  []string
			Export  string
		}
		if err := json.Unmarshal(output, &selected); err != nil ||
			!equalDiscoveryStrings(selected.GoFiles, []string{"probe.go"}) ||
			!equalDiscoveryStrings(selected.SFiles, []string{"cpu.s", "probe.s"}) || selected.Export == "" {
			t.Fatalf("original %s selected a different source/export: %+v %v", target, selected, err)
		}
		digest, err := discoveryFeatureFileSHA256(selected.Export)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("original Go accepted %s source_sha=%s export_sha=%s zip_sha=%s h1=%s",
			target, discoveryFeatureBytesSHA256([]byte(sources["probe.s"])), digest,
			discoveryFeatureBytesSHA256(mustReadOrdinaryCPPFixture(t, download.Zip)), archiveSum)
	}

	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: translator, LLC: llc, Targets: targets,
		CandidateTimeout: 3 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("Go-accepted original ordinary CPP macros failed production: %v", err)
	}
	if matrix.Success < len(targets) || matrix.NotApplicable != 0 || len(matrix.FeatureConsumption) != len(configs) {
		t.Fatalf("original complete scopes lost: objects=%d N/A=%d configurations=%d consumers=%d",
			matrix.Success, matrix.NotApplicable, len(configs), len(matrix.FeatureConsumption))
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
		FeatureConsumption: matrix.FeatureConsumption, featureInventory: inventory,
	}
	if err := validateOrdinaryProfileResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatal(err)
	}
	checkSelectedSiblingReportReaders(t, candidate, result, targets, inventory)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	originalBytes := 0
	for _, source := range result.OrdinarySelectionPlan.CPPInputs.Sources {
		originalBytes += len(*source.Original)
	}
	t.Logf("actual ordinary full11 objects=%d profiles=%d deduplicated_original_bytes=%d result_json_bytes=%d",
		result.Translations, len(result.FeatureProfiles), originalBytes, len(encoded))
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"delete_consumer_original_protocol": func(copy *discoveryCorpusResult) {
			for _, proof := range copy.FeatureConsumption {
				proof.CPPSourceProtocol = ""
			}
		},
		"paired_delete_active_absence": func(copy *discoveryCorpusResult) {
			for _, proof := range copy.FeatureConsumption {
				proof.CPPIncludeSearchMisses = nil
				for index := range proof.CPP {
					proof.CPP[index].ExpandedSearchMisses = nil
				}
			}
		},
		"paired_active_absence_downgrade": func(copy *discoveryCorpusResult) {
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
		"delete_protocol_and_graph": func(copy *discoveryCorpusResult) {
			copy.OrdinarySelectionPlan.CPPSourceProtocol = ""
			copy.OrdinarySelectionPlan.CPPInputs = nil
		},
		"paired_legacy_downgrade": func(copy *discoveryCorpusResult) {
			copy.OrdinarySelectionPlan.CPPSourceProtocol = discoveryDeferredCPPInputsProtocol
			copy.OrdinarySelectionPlan.CPPInputs.Protocol = discoveryDeferredCPPInputsProtocol
		},
		"delete_original_only": func(copy *discoveryCorpusResult) {
			input := copy.OrdinarySelectionPlan.CPPInputs.Sources["module/macros.h"]
			input.Original = nil
			copy.OrdinarySelectionPlan.CPPInputs.Sources["module/macros.h"] = input
		},
		"change_macro_body": func(copy *discoveryCorpusResult) {
			input := copy.OrdinarySelectionPlan.CPPInputs.Sources["module/macros.h"]
			changed := strings.Replace(*input.Original, "amdMarker", "forgedMarker", 1)
			if changed == *input.Original {
				t.Fatal("macro mutation did not change original bytes")
			}
			input.Original = &changed
			copy.OrdinarySelectionPlan.CPPInputs.Sources["module/macros.h"] = input
		},
		"paired_output_and_input_delete": func(copy *discoveryCorpusResult) {
			for _, proof := range copy.FeatureConsumption {
				for index := range proof.CPP {
					delete(proof.CPP[index].Inputs, "module/choice.h")
					proof.CPP[index].ExpandedSHA256 = strings.Repeat("a", 64)
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
				t.Fatal("mutated ordinary original source/consumer proof was accepted")
			}
		})
	}
}

func mustReadOrdinaryCPPFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
