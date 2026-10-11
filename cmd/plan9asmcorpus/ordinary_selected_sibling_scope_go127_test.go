//go:build go1.27

package main

import (
	"context"

	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrdinaryProducerNonemptyAssemblySiblingsFiveArchitectures(t *testing.T) {

	compilerEnvironment := os.Environ()
	candidate := discoveryCandidate{Module: "example.invalid/nonempty-sibling", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
	sources := map[string]string{
		"go.mod":       "module example.invalid/nonempty-sibling\n\ngo 1.20\n",
		"probe.go":     "package sibling\nfunc Probe()\nfunc Fast()\n",
		"probe.s":      "TEXT ·Probe(SB),4,$0-0\nRET\n",
		"cpu.s":        "// original nonempty placeholder\n",
		"white.s":      "\n \t\n",
		"macro.s":      "#ifdef NEVER_ENABLED\nTEXT ·NotSelected(SB),4,$0-0\nRET\n#endif\n",
		"empty.s":      "",
		"_ignored.s":   "// not selected by Go\n",
		"fast_amd64.s": "//go:build amd64.v3\n\n#ifdef GOAMD64_v4\nTEXT ·Fast(SB),4,$0-0\nNOP\nRET\n#else\nTEXT ·Fast(SB),4,$0-0\nRET\n#endif\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	proxy := t.TempDir()
	versions := filepath.Join(proxy, candidate.Module, "@v")
	if err := os.MkdirAll(versions, 0755); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(download.Zip)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"v1.0.0.mod": []byte(sources["go.mod"]), "v1.0.0.zip": archive,
		"v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2026-10-02T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(versions, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off") // Only this owned fixture module, never an external package.
	t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "modules"))
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "plan9asmll")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, _, err = runDiscoveryMachineCommand(ctx, filepath.Join(root, "cmd", "plan9asmll"), compilerEnvironment,
		"go", "build", "-p=2", "-o", binary, ".")
	if err != nil {
		t.Fatal(err)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: targets, CandidateTimeout: 2 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Success != 30 || matrix.NotApplicable != 0 || len(configs) != 7 || len(matrix.FeatureConsumption) != 7 {
		t.Fatalf("actual nonempty/profile object scopes were lost: successes=%d N/A=%d configurations=%d consumers=%d",
			matrix.Success, matrix.NotApplicable, len(configs), len(matrix.FeatureConsumption))
	}
	for _, proof := range matrix.FeatureConsumption {
		for _, cpp := range proof.CPP {
			if cpp.File == "cpu.s" || cpp.File == "white.s" || cpp.File == "macro.s" {
				if cpp.Emission != "symbol_free" || cpp.EmptyAssembly == nil {
					t.Fatalf("nonempty sibling lacks its actual Go symbol-free object/listing: %#v", cpp)
				}
			}
			if cpp.File == "empty.s" || strings.HasPrefix(cpp.File, "_") {
				t.Fatalf("unselected/zero sibling inflated translation scopes: %s", cpp.File)
			}
		}
	}
	inventory := &discoveryFeatureInventory{}
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: discoveryConfigurationAsmFiles(configs),
		BuildConfigurations: configs, Translations: matrix.Success, OrdinarySelectionPlan: matrix.OrdinarySelectionPlan,
		FeatureProfiles: refs, FeatureConsumption: matrix.FeatureConsumption, featureInventory: inventory,
	}
	if err := validateOrdinaryProfileResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatal(err)
	}
	checkSelectedSiblingReportReaders(t, candidate, result, targets, inventory)
	for _, omit := range []string{"cpu.s", "white.s", "macro.s", "fast_amd64.s"} {
		copy := result
		copy.OrdinarySelectionPlan = cloneSelectedSiblingPlan(t, result.OrdinarySelectionPlan)
		copy.OrdinarySelectionPlan.TestedAsmFiles = subtractDiscoveryStrings(copy.OrdinarySelectionPlan.TestedAsmFiles, []string{omit})
		if err := validateOrdinaryProfileResult(copy, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
			t.Fatalf("offline reader accepted omitted original nonempty sibling %s", omit)
		}
	}
	legacy := result
	legacy.OrdinarySelectionPlan = cloneSelectedSiblingPlan(t, result.OrdinarySelectionPlan)
	legacy.OrdinarySelectionPlan.Protocol, legacy.OrdinarySelectionPlan.TestedAsmFiles = ordinarySelectionProtocol, nil
	if err := validateOrdinaryProfileResult(legacy, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
		t.Fatal("historical v1 was relabeled as complete sibling coverage")
	}
	unconsumed := result
	unconsumed.FeatureConsumption = result.FeatureConsumption[1:]
	if err := validateOrdinaryProfileResult(unconsumed, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
		t.Fatal("unconsumed macro-empty profile received pass credit")
	}
}
