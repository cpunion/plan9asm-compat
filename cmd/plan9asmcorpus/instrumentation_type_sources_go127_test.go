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

// This fixture owns imported SDK source/export and independent consumer
// transport, not an exhaustive ARM64 CPU planning stress test. AMD64 still
// observes all four legal CPU proposals before identical output shares one
// object. ARM64's complete actual query/selection domain is independently
// required by TestInstrumentationNativeHeaderImportedCPUConstantKeepsDistinctOutputScopes;
// its original SDK imports and all five target layouts have separate guards.
func TestInstrumentationImportedTypesCorpusRetainsOriginalSourceInput(t *testing.T) {
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	_, stderr, err := gotoolprofile.RunBounded(ctx, filepath.Join(root, "cmd", "plan9asmll"), os.Environ(),
		"go", "build", "-p=1", "-o", translator, ".")
	if err != nil {
		t.Fatalf("build current source translator: %v; %s", err, stderr)
	}
	candidate := discoveryCandidate{Module: "example.invalid/imported-types", Version: "v1.0.0", AsmFiles: []string{"probe_amd64.s"}}
	sources := map[string]string{
		"go.mod":        "module example.invalid/imported-types\n\ngo 1.20\n",
		"probe.go":      "//go:build race && !cgo\n\npackage importedtypes\nimport (\"math/bits\"; renamed \"syscall\")\nconst answer = bits.UintSize\nfunc Probe(x uint64) renamed.Errno\n",
		"probe_amd64.s": "//go:build race && !cgo\n\n#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-16\nMOVQ x+0(FP),AX\nADDQ $const_answer,AX\nMOVQ AX,ret+8(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	const target = "darwin/amd64"
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: translator, LLC: llc, Targets: []string{target}, CandidateTimeout: 4 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	if matrix.InstrumentationTranslations != 1 || matrix.Success != 1 || len(configs) != 0 {
		mode := matrix.OrdinarySelectionPlan.InstrumentationPlan
		t.Fatalf("independent imported source requires one mode object: objects=%d instrumentation=%d ordinary_configs=%d base_requirements=%d cpp_requirements=%d outcomes=%d",
			matrix.Success, matrix.InstrumentationTranslations, len(configs), len(mode.Requirements), len(mode.CPPRequirements), len(mode.Outcomes))
	}
	mode := matrix.OrdinarySelectionPlan.InstrumentationPlan
	testInstrumentationImportedSDKQueryScopes(t, mode)
	if len(mode.Outcomes) != 1 || mode.Outcomes[0].TypeSources == nil {
		t.Fatal("producer did not retain its independent original imported source collection")
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed, DiscoveredAsmFiles: candidate.AsmFiles,
		ApplicableAsmFiles: discoveryInstrumentationExecutedFiles(matrix.OrdinarySelectionPlan), Translations: matrix.Success,
		InstrumentationTranslations: matrix.InstrumentationTranslations, SourceNotApplicableItems: matrix.SourceNotApplicableItems,
		OrdinarySelectionPlan: matrix.OrdinarySelectionPlan, FeatureProfiles: refs,
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip discoveryCorpusResult
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatal(err)
	}
	roundtrip.featureInventory = inventory
	if err := validateOrdinaryProfileResult(roundtrip, []string{target}, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatal(err)
	}
	testInstrumentationCorpusTransport(t, roundtrip, inventory, target)
	testInstrumentationNativeHeaderPlanningMutations(t, roundtrip, inventory, target)
	for name, change := range map[string]func(*discoveryInstrumentationOutcome){
		"original collection deleted": func(p *discoveryInstrumentationOutcome) { p.TypeSources = nil },
		"source protocol downgraded":  func(p *discoveryInstrumentationOutcome) { p.TypeSources.Protocol = "unverified" },
		"actual SDK bytes changed": func(p *discoveryInstrumentationOutcome) {
			for index := range p.TypeSources.Dependencies {
				dep := &p.TypeSources.Dependencies[index]
				if dep.Dependency.Source.PackagePath == "syscall" {
					for file := range dep.Contents {
						dep.Contents[file] += "\n// changed original SDK bytes\n"
						return
					}
				}
			}
		},
		"paired producer consumer export": func(p *discoveryInstrumentationOutcome) {
			for _, metadata := range []*gotoolprofile.InstrumentationMetadataProof{p.Query.Metadata, p.Objects.Metadata, p.Objects.Consumption.Metadata} {
				metadata.Dependencies[0].Source.ExportSHA256 = strings.Repeat("0", 64)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[0])
			changed.featureInventory = inventory
			if err := validateOrdinaryProfileResult(changed, []string{target}, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatal("paired metadata or a deleted original source capture bypassed strict report readback")
			}
		})
	}
}
