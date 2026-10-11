//go:build go1.27

package main

import (
	"context"

	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestDataOnlySiblingPreservesActualSupplementalDeclarationQuery(t *testing.T) {

	compilerEnv := os.Environ()
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "plan9asmll")
	command := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", binary, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build owned current translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	candidate := discoveryCandidate{
		Module: "example.invalid/data-only-testdecl", Version: "v1.0.0",
		AsmFiles: []string{"empty.s", "probe_386.s", "probe_amd64.s", "probe_arm.s", "probe_arm64.s", "probe_wasm.s", "tables.s"},
	}
	const inlineData = "DATA ·inline+0(SB)/4,$21\nGLOBL ·inline(SB),$4\n"
	sources := map[string]string{
		"go.mod":        "module example.invalid/data-only-testdecl\n\ngo 1.20\n",
		"probe.go":      "package probe\n",
		"decl_test.go":  "package probe\nfunc Echo(x uint32) uint32\n",
		"empty.s":       "// Original nonempty source with no native symbols.\n",
		"probe_amd64.s": "TEXT ·Echo(SB),4,$0-12\nMOVL x+0(FP),AX\nMOVL AX,ret+8(FP)\nRET\n" + inlineData,
		"probe_386.s":   "TEXT ·Echo(SB),4,$0-8\nMOVL x+0(FP),AX\nMOVL AX,ret+4(FP)\nRET\n" + inlineData,
		"probe_arm.s":   "TEXT ·Echo(SB),4,$0-8\nMOVW x+0(FP),R0\nMOVW R0,ret+4(FP)\nRET\n" + inlineData,
		"probe_arm64.s": "TEXT ·Echo(SB),4,$0-12\nMOVWU x+0(FP),R0\nMOVW R0,ret+8(FP)\nRET\n" + inlineData,
		"probe_wasm.s":  "TEXT ·Echo(SB),4,$0-12\nMOVW x+0(FP),R0\nMOVW R0,ret+8(FP)\nRET\n" + inlineData,
		"tables.s": "DATA ·payload+0(SB)/8,$0x123456789abcdef0\nGLOBL ·payload(SB),$8\n" +
			"GLOBL ·zero(SB),$16\nDATA local<>+0(SB)/4,$7\nGLOBL local<>(SB),8,$4\n" +
			"#ifdef GOAMD64_v3\nDATA ·profile+0(SB)/4,$3\n#else\nDATA ·profile+0(SB)/4,$1\n#endif\nGLOBL ·profile(SB),$4\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, download, sources["go.mod"])
	targets := []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"}
	for _, target := range targets {
		parts := strings.Split(target, "/")
		env := replaceEnv(os.Environ(), map[string]string{
			"GOOS": parts[0], "GOARCH": parts[1], "CGO_ENABLED": "0",
		})
		for _, args := range [][]string{
			{"list", "-export", "-json", "."},
			{"list", "-test", "-export", "-json", "."},
		} {
			if _, stderr, err := gotoolprofile.RunBounded(ctx, download.Dir, env, "go", args...); err != nil {
				t.Fatalf("actual original Go %s %v: %v\n%s", target, args, err, stderr)
			}
		}
	}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc,
		Targets: targets, CandidateTimeout: 3 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("actual test declaration plus DATA sibling lost query/final agreement: %v", err)
	}
	if matrix.Success != 18 || len(matrix.FeatureConsumption) != 6 {
		t.Fatalf("query metadata cannot add to three real objects per target: %#v", matrix)
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles,
		BuildConfigurations: configs, Translations: matrix.Success,
		OrdinarySelectionPlan: matrix.OrdinarySelectionPlan,
		FeatureProfiles:       refs, FeatureConsumption: matrix.FeatureConsumption, featureInventory: inventory,
	}
	if err := validateOrdinaryProfileResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatalf("original mixed-source result failed strict reader replay: %v", err)
	}
	for _, consumer := range matrix.FeatureConsumption {
		dependency := consumer.TestDependencies
		if dependency == nil || dependency.Query == nil || len(dependency.Query.Selection.Outputs) != 0 ||
			len(dependency.Query.Selection.TestDeclarations) != 0 {
			t.Fatal("native query witness falsely acquired final declarations or LLVM output")
		}
		var dataOnly, empty, mixed int
		byFile := make(map[string]gotoolprofile.CPPProof)
		for _, previous := range dependency.Query.Selection.CPP {
			byFile[previous.File] = previous
		}
		for _, cpp := range consumer.CPP {
			previous := byFile[cpp.File]
			if previous.Emission != cpp.Emission ||
				!reflect.DeepEqual(previous.DataOnlyAssembly, cpp.DataOnlyAssembly) ||
				!reflect.DeepEqual(previous.EmptyAssembly, cpp.EmptyAssembly) {
				t.Fatal("query and final native identity are not identical")
			}
			switch cpp.Emission {
			case "data_only":
				dataOnly++
				if cpp.File != "tables.s" || len(cpp.Signatures) != 0 ||
					cpp.DataOnlyAssembly == nil || len(cpp.DataOnlyAssembly.Symbols) != 4 {
					t.Fatal("DATA/BSS/static symbols acquired TEXT signatures or lost native evidence")
				}
			case "symbol_free":
				empty++
			case "assembly":
				mixed++
				if len(cpp.Signatures) != 1 || cpp.Signatures[0].Role != "inpackage_test_decl" || cpp.DataOnlyAssembly != nil {
					t.Fatal("same-file mixed TEXT/DATA erased its actual test signature")
				}
			}
		}
		if dataOnly != 1 || empty != 1 || mixed != 1 {
			t.Fatalf("incomplete source emission family: DATA=%d empty=%d TEXT=%d", dataOnly, empty, mixed)
		}
	}
	checkDataOnlyQueryReaderMutants(t, result, targets, inventory)
}
