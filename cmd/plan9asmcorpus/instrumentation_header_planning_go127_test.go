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

// The dependency changes a header constant, not a root CPP branch. The owned
// file proxy is first-party compiler evidence, not an official SumDB receipt.
func TestInstrumentationNativeHeaderImportedCPUConstantKeepsDistinctOutputScopes(t *testing.T) {
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	_, stderr, err := gotoolprofile.RunBounded(ctx, filepath.Join(root, "cmd", "plan9asmll"), os.Environ(), binary, "build", "-p=2", "-o", translator, ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("build actual CLI: %v; %s", err, stderr)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	candidate := discoveryCandidate{Module: "example.invalid/cpu-header", Version: "v1.0.0", AsmFiles: []string{"probe_arm64.s"}}
	sources := map[string]string{
		"go.mod":        "module example.invalid/cpu-header\n\ngo 1.20\nrequire example.invalid/cpu-layout v1.0.0\n",
		"probe.go":      "//go:build race && !cgo\n\npackage cpuheader\nimport shape \"example.invalid/cpu-layout/model\"\nconst Answer = shape.Words\nfunc Probe(x uint64) uint64\n",
		"probe_arm64.s": "//go:build race && !cgo\n\n#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-16\nMOVD x+0(FP),R0\nADD $const_Answer,R0\nMOVD R0,ret+8(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	foreign := discoveryCandidate{Module: "example.invalid/cpu-layout", Version: "v1.0.0"}
	metadata := "module example.invalid/cpu-layout\n\ngo 1.20\n"
	dependencySources := map[string]string{
		"go.mod":        metadata,
		"model/base.go": "//go:build !arm64.v8.1\n\npackage model\nconst Words = 1\n",
		"model/wide.go": "//go:build arm64.v8.1\n\npackage model\nconst Words = 2\n",
	}
	dependency := fixtureProfileModuleDownload(t, foreign, dependencySources)
	versions := filepath.Join(strings.TrimPrefix(os.Getenv("GOPROXY"), "file://"), foreign.Module, "@v")
	if err := os.MkdirAll(versions, 0700); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(dependency.Zip)
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"v1.0.0.mod": []byte(metadata), "v1.0.0.zip": archive,
		"v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2026-10-01T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(versions, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, stderr, err = gotoolprofile.RunBounded(ctx, t.TempDir(), os.Environ(), binary, "mod", "download", "-json", foreign.Module+"@"+foreign.Version)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("exact owned dependency: %v; %s", err, stderr)
	}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{RepoRoot: root, Translator: translator, LLC: llc,
		Targets: []string{"darwin/arm64"}, CandidateTimeout: 4 * time.Minute}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	proof := matrix.OrdinarySelectionPlan.InstrumentationPlan
	// Unlike the SDK transport fixture, this owns all 32 actual ARM64 CPU
	// proposals, source-selected property differences and object consumers.
	testInstrumentationARM64OriginalQueryScopes(t, proof, dependencySources)
	values := make(map[string]bool)
	for _, query := range proof.HeaderPlanning.Queries {
		values[query.Metadata.Headers[0].Header.Definitions["const_Answer"]] = true
	}
	if len(values) != 2 || !values["1"] || !values["2"] {
		t.Fatalf("actual same-mode native headers did not observe the CPU-selected source change: %v", values)
	}
	if matrix.InstrumentationTranslations != 2 || matrix.Success != 2 || len(configs) != 0 || len(proof.CPPRequirements) != 1 {
		t.Fatalf("distinct actual CPP outputs collapsed: objects=%d instrumentation=%d ordinary=%d CPP=%d header_values=%v",
			matrix.Success, matrix.InstrumentationTranslations, len(configs), len(proof.CPPRequirements), values)
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
	result.featureInventory = inventory
	if err := validateOrdinaryProfileResult(result, []string{"darwin/arm64"}, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatal(err)
	}
	testInstrumentationCorpusTransport(t, result, inventory, "darwin/arm64")
	testInstrumentationNativeHeaderPlanningMutations(t, result, inventory, "darwin/arm64")
	testInstrumentationARM64QueryOmissions(t, result, inventory, "darwin/arm64")
}

func testInstrumentationNativeHeaderPlanningMutations(t *testing.T, result discoveryCorpusResult, inventory *discoveryFeatureInventory, target string) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	role := result.OrdinarySelectionPlan.InstrumentationPlan.HeaderPlanning
	if role == nil || len(role.Queries) == 0 {
		t.Fatal("actual missing header was reduced without its independent query-only role")
	}
	roleBytes, err := json.Marshal(role)
	if err != nil {
		t.Fatal(err)
	}
	contentBytes := 0
	for _, text := range role.Contents {
		contentBytes += len(text)
	}
	t.Logf("actual planning-only role: queries=%d unique_full_files=%d full_bytes=%d serialized_role_bytes=%d result_bytes=%d objects=%d",
		len(role.Queries), len(role.Contents), contentBytes, len(roleBytes), len(encoded), result.InstrumentationTranslations)
	mutations := map[string]func(*discoveryInstrumentationPlan){
		"query role deleted": func(p *discoveryInstrumentationPlan) { p.HeaderPlanning = nil },
		"role downgraded": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Protocol = "unproved"
		},
		"query sources deleted": func(p *discoveryInstrumentationPlan) { p.HeaderPlanning.Contents = nil },
		"paired all queries deleted": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries, p.HeaderPlanning.Contents = nil, map[string]string{}
		},
		"duplicate query": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries = append(p.HeaderPlanning.Queries, p.HeaderPlanning.Queries[0])
		},
		"extra unconsumed query": func(p *discoveryInstrumentationPlan) {
			query := p.HeaderPlanning.Queries[0]
			query.Assembly = "unselected.s"
			p.HeaderPlanning.Queries = append(p.HeaderPlanning.Queries, query)
		},
		"query output scope deleted": func(p *discoveryInstrumentationPlan) {
			if len(p.CPPRequirements) != 0 {
				p.CPPRequirements = []discoveryInstrumentationRequirement{}
			} else {
				p.CPPRequirements = nil
			}
		},
		"different mode": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].Requirement.Mode = gotoolprofile.InstrumentationASan
		},
		"different cgo": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].Requirement.CGO = "1"
		},
		"different target": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].Requirement.Target = "linux/amd64"
		},
		"different tags": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].Requirement.Tags = []string{"unobserved"}
		},
		"different cpu": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].Requirement.Overrides = map[string]string{"GOARM64": "v9.5"}
		},
		"sdk registration bytes": func(p *discoveryInstrumentationPlan) {
			for name := range p.HeaderPlanning.Rules.SourceSHA256 {
				p.HeaderPlanning.Rules.SourceSHA256[name] = strings.Repeat("0", 64)
				break
			}
		},
		"sdk version borrowed": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Rules.GoVersion = "go1.20.14"
		},
		"metadata object role invented": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].Properties.Types = p.Outcomes[0].TypeSources
		},
		"property source references deleted": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].PropertyTypes.Packages = nil
		},
		"signature role borrowed": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].PropertyTypes = p.HeaderPlanning.Queries[0].Signatures
		},
		"module language changed": func(p *discoveryInstrumentationPlan) {
			query := &p.HeaderPlanning.Queries[0]
			digest := query.ModuleMetadata["original"]
			p.HeaderPlanning.Contents[digest] = strings.Replace(p.HeaderPlanning.Contents[digest], "1.20", "1.21", 1)
		},
		"module metadata references deleted": func(p *discoveryInstrumentationPlan) {
			p.HeaderPlanning.Queries[0].ModuleMetadata = nil
		},
		"extra module metadata references": func(p *discoveryInstrumentationPlan) {
			query := &p.HeaderPlanning.Queries[0]
			query.ModuleMetadata["unconsumed"] = query.ModuleMetadata["original"]
		},
		"extra original bytes": func(p *discoveryInstrumentationPlan) {
			text := "unconsumed original input"
			p.HeaderPlanning.Contents[discoveryFeatureBytesSHA256([]byte(text))] = text
		},
		"complete original bytes changed": func(p *discoveryInstrumentationPlan) {
			for digest, text := range p.HeaderPlanning.Contents {
				p.HeaderPlanning.Contents[digest] = text + "\n"
				break
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(changed.OrdinarySelectionPlan.InstrumentationPlan)
			changed.featureInventory = inventory
			if err := validateOrdinaryProfileResult(changed, []string{target}, result.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatal("mutated planning query acquired an execution scope or omission authority")
			}
		})
	}
}
