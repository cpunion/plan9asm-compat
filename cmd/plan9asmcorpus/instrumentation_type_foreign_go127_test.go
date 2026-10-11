//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// This is an owned first-party file proxy. GOSUMDB=off here is not a production
// authentication certificate; the producer's unchanged official verifier is
// exercised separately by its existing signed-lookup/ZIP tests.
func TestInstrumentationForeignTypesCorpusOriginalQueryAndObjects(t *testing.T) {
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	_, stderr, err := gotoolprofile.RunBounded(ctx, filepath.Join(root, "cmd", "plan9asmll"), os.Environ(),
		binary, "build", "-p=2", "-o", translator, ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("build actual source CLI: %v; %s", err, stderr)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	for _, selectors := range []bool{true, false} {
		t.Run(map[bool]string{true: "bodyless_type", false: "ordinary_body_only"}[selectors], func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/foreign-types", Version: "v1.0.0", AsmFiles: []string{"probe_arm64.s"}}
			declaration := "const Answer = shape.Words\nfunc Probe(x shape.Word) uint64\n"
			if !selectors {
				declaration = "const Answer = 2\nfunc Probe(x uint64) uint64\nfunc Body() uint64 { return uint64(shape.Header{}.Hi) + uint64(shape.Words) }\n"
			}
			sources := map[string]string{
				"go.mod":        "module example.invalid/foreign-types\n\ngo 1.20\nrequire example.invalid/layout v1.0.0\n",
				"probe.go":      "//go:build race && !cgo\n\npackage foreigntypes\nimport shape \"example.invalid/layout/model\"\n" + declaration,
				"probe_arm64.s": "//go:build race && !cgo\n\n#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-16\nMOVD x+0(FP),R0\nADD $const_Answer,R0\nMOVD R0,ret+8(FP)\nRET\n",
			}
			download := fixtureProfileModuleDownload(t, candidate, sources)
			configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
			foreign := discoveryCandidate{Module: "example.invalid/layout", Version: "v1.0.0"}
			foreignMod := "module example.invalid/layout\n\ngo 1.20\n"
			original := fixtureProfileModuleDownload(t, foreign, map[string]string{
				"go.mod":          foreignMod,
				"model/layout.go": "package model\nconst Words = 2\ntype Word uint64\ntype Header struct { Lo uint32; Pad [Words]byte; Hi uint16 }\n",
			})
			proxy := strings.TrimPrefix(os.Getenv("GOPROXY"), "file://")
			versions := filepath.Join(proxy, foreign.Module, "@v")
			if err := os.MkdirAll(versions, 0700); err != nil {
				t.Fatal(err)
			}
			zipBytes, err := os.ReadFile(original.Zip)
			if err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string][]byte{
				"v1.0.0.mod": []byte(foreignMod), "v1.0.0.zip": zipBytes,
				"v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2026-10-01T00:00:00Z"}`),
			} {
				if err := os.WriteFile(filepath.Join(versions, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Resolve only this exact dependency before strict stderr/metadata
			// capture; this download itself is neither a query nor an object pass.
			asset, stderr, err := gotoolprofile.RunBounded(ctx, t.TempDir(), os.Environ(), binary, "mod", "download", "-json", foreign.Module+"@"+foreign.Version)
			if err != nil || len(stderr) != 0 {
				t.Fatalf("owned exact fixture download: %v; %s", err, stderr)
			}
			t.Logf("actual first-party stock-Go download (not official SumDB proof): %s", asset)
			const target = "darwin/arm64"
			matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
				RepoRoot: root, Translator: translator, LLC: llc, Targets: []string{target}, CandidateTimeout: 4 * time.Minute,
			}, candidate, filepath.Join(t.TempDir(), "candidate"))
			if err != nil {
				t.Fatal(err)
			}
			if matrix.Success != 1 || matrix.InstrumentationTranslations != 1 || len(configs) != 0 {
				t.Fatal("foreign original source became ordinary completion or lost its actual LLVM object")
			}
			plan := matrix.OrdinarySelectionPlan.InstrumentationPlan
			if len(plan.Outcomes) != 1 || plan.Outcomes[0].TypeSources == nil || len(plan.Outcomes[0].TypeSources.SourceModules) != 1 {
				t.Fatal("actual same-mode foreign graph was not captured independently of signature selectors")
			}
			proof := plan.Outcomes[0].TypeSources
			if proof.Protocol != gotoolprofile.InstrumentationTypeSourcesProtocol || proof.Dependencies[0].SourceRootID != foreign.Module+"@"+foreign.Version {
				t.Fatal("foreign graph lost actual declared/source module identity")
			}
			if len(matrix.OrdinarySelectionPlan.TestDeclarationQueries) != 0 {
				t.Fatal("ordinary type-only resources acquired a supplemental test role")
			}
			inventory := newDiscoveryFeatureInventory()
			refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
			if err != nil {
				t.Fatal(err)
			}
			result := discoveryCorpusResult{Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
				DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: discoveryInstrumentationExecutedFiles(matrix.OrdinarySelectionPlan),
				Translations: matrix.Success, InstrumentationTranslations: matrix.InstrumentationTranslations,
				SourceNotApplicableItems: matrix.SourceNotApplicableItems, OrdinarySelectionPlan: matrix.OrdinarySelectionPlan, FeatureProfiles: refs}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			result.featureInventory = inventory
			if err := validateOrdinaryProfileResult(result, []string{target}, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
				t.Fatal(err)
			}
			testInstrumentationCorpusTransport(t, result, inventory, target)
			for name, mutate := range map[string]func(*gotoolprofile.InstrumentationTypeSourceProof){
				"paired entire capture deleted": func(p *gotoolprofile.InstrumentationTypeSourceProof) {
					*p = gotoolprofile.InstrumentationTypeSourceProof{}
				},
				"modules deleted": func(p *gotoolprofile.InstrumentationTypeSourceProof) { p.SourceModules = nil },
				"v1 downgrade": func(p *gotoolprofile.InstrumentationTypeSourceProof) {
					p.Protocol = "actual_go_instrumentation_type_sources_v1"
				},
				"same bytes wrong source version": func(p *gotoolprofile.InstrumentationTypeSourceProof) { p.SourceModules[0].SourceVersion = "v1.0.1" },
				"directory closure truncated":     func(p *gotoolprofile.InstrumentationTypeSourceProof) { delete(p.SourceModules[0].Directories, "model") },
				"export changed": func(p *gotoolprofile.InstrumentationTypeSourceProof) {
					p.Dependencies[0].Dependency.Source.ExportSHA256 = strings.Repeat("0", 64)
				},
			} {
				t.Run(name, func(t *testing.T) {
					var changed discoveryCorpusResult
					if err := json.Unmarshal(encoded, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(changed.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[0].TypeSources)
					changed.featureInventory = inventory
					if reflect.DeepEqual(changed.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[0].TypeSources, proof) ||
						validateOrdinaryProfileResult(changed, []string{target}, matrix.OrdinarySelectionPlan.GoVersion) == nil {
						t.Fatal("reader accepted deleted/downgraded foreign original source evidence")
					}
				})
			}
		})
	}
}
