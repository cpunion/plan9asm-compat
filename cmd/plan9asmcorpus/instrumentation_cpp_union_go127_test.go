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

// Every profile first has its own original stock-Go export. The corpus must
// separately consume all four mode-specific CPP/LLVM objects: ordinary CPU
// observations and one baseline race object cannot stand in for that union.
func TestInstrumentationCPPCPUUnionOriginalGoAndObjects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	build := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", translator, ".")
	build.Dir = filepath.Join(root, "cmd", "plan9asmll")
	build.Env = os.Environ()
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual current translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	candidate := discoveryCandidate{
		Module: "example.invalid/instrumentation-cpu", Version: "v1.0.0",
		AsmFiles: []string{"probe_amd64.s"},
	}
	sources := map[string]string{
		"go.mod": "module example.invalid/instrumentation-cpu\n\ngo 1.20\n",
		"probe.go": `//go:build race && !cgo

package fixture
const bias = 41
func Probe(x uint64) uint64
`,
		"probe_amd64.s": `//go:build race && !cgo

#include "go_asm.h"
#define INCLUDE_TOOL \
#include "../../src/runtime/go_tls.h" \

INCLUDE_TOOL
TEXT ·Probe(SB),$0-16
MOVQ x+0(FP), AX
#ifdef GOAMD64_v1
ADDQ $1, AX
#endif
#ifdef GOAMD64_v2
ADDQ $2, AX
#endif
#ifdef GOAMD64_v3
ADDQ $3, AX
#endif
#ifdef GOAMD64_v4
ADDQ $4, AX
#endif
ADDQ $const_bias, AX
MOVQ AX, ret+8(FP)
RET
`,
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	for _, level := range []string{"v1", "v2", "v3", "v4"} {
		original := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-p=1", "-race", "-export", "-json", ".")
		original.Dir = download.Dir
		original.Env = replaceEnv(os.Environ(), map[string]string{
			"GOOS": "darwin", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOAMD64": level,
		})
		output, err := original.Output()
		if err != nil {
			if exited, ok := err.(*exec.ExitError); ok {
				t.Fatalf("original mode %s export: %v\n%s", level, err, exited.Stderr)
			}
			t.Fatal(err)
		}
		var selected struct {
			GoFiles []string
			SFiles  []string
			Export  string
		}
		if err := json.Unmarshal(output, &selected); err != nil ||
			!equalDiscoveryStrings(selected.GoFiles, []string{"probe.go"}) ||
			!equalDiscoveryStrings(selected.SFiles, candidate.AsmFiles) || selected.Export == "" {
			t.Fatalf("original %s mode source/export selection changed: %+v %v", level, selected, err)
		}
		if stat, err := os.Stat(selected.Export); err != nil || !stat.Mode().IsRegular() || stat.Size() == 0 {
			t.Fatalf("original %s mode physical export is missing: %v", level, err)
		}
		t.Logf("original Go accepted the complete %s race CPP source", level)
	}
	matrix, _, configurations, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: translator, LLC: llc, Targets: []string{"darwin/amd64"},
		CandidateTimeout: 6 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("original-Go-accepted CPU mode union is not covered: %v", err)
	}
	if matrix.Success != 4 || matrix.InstrumentationTranslations != 4 ||
		len(configurations) != 0 || len(matrix.FeatureConsumption) != 0 {
		t.Fatalf("four independently consumed mode objects were lost or relabeled as ordinary: success=%d mode=%d", matrix.Success, matrix.InstrumentationTranslations)
	}
	inventory := newDiscoveryFeatureInventory()
	references, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles,
		ApplicableAsmFiles: discoveryInstrumentationExecutedFiles(matrix.OrdinarySelectionPlan),
		Translations:       matrix.Success, InstrumentationTranslations: matrix.InstrumentationTranslations,
		BuildConfigurations: configurations, SourceNotApplicableItems: matrix.SourceNotApplicableItems,
		OrdinarySelectionPlan: matrix.OrdinarySelectionPlan, FeatureProfiles: references,
		FeatureConsumption: matrix.FeatureConsumption,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var replay discoveryCorpusResult
	if err := json.Unmarshal(encoded, &replay); err != nil {
		t.Fatal(err)
	}
	replay.featureInventory = inventory
	if err := validateOrdinaryProfileResult(replay, []string{"darwin/amd64"}, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatalf("independent mode CPU union report replay: %v", err)
	}
	testInstrumentationCorpusTransport(t, replay, inventory, "darwin/amd64")
	seen := make(map[string]bool)
	for _, outcome := range replay.OrdinarySelectionPlan.InstrumentationPlan.Outcomes {
		observation := replay.OrdinarySelectionPlan.InstrumentationPlan.Observations[outcome.ObservationID]
		if observation == nil || outcome.Objects == nil || outcome.Objects.ObjectCount != 1 ||
			outcome.Query == nil || outcome.Status != "llvm_objects_only" || outcome.Error != "" {
			t.Fatal("union scope lacks its independent actual mode/query/LLVM consumption")
		}
		level := observation.Early.Environment["GOAMD64"]
		if seen[level] || !strings.HasPrefix(level, "v") {
			t.Fatal("duplicate or unbound actual CPU mode environment")
		}
		seen[level] = true
	}
	if len(seen) != 4 {
		t.Fatalf("mode CPU denominator is incomplete: %v", seen)
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"query reused as objects": func(p *discoveryCorpusResult) {
			outcome := &p.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[0]
			outcome.Objects = outcome.Query
		},
		"null expanded operand set": func(p *discoveryCorpusResult) {
			p.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[0].Objects.Consumption.Files[0].CPP.ExpandedSearchMisses = nil
		},
		"paired delete original and expanded operands": func(p *discoveryCorpusResult) {
			plan := p.OrdinarySelectionPlan.InstrumentationPlan
			plan.CPPInputs = nil
			for index := range plan.Outcomes {
				plan.Outcomes[index].Objects.Consumption.Files[0].CPP.ExpandedSearchMisses = nil
			}
		},
		"downgrade expanded operand to physical": func(p *discoveryCorpusResult) {
			miss := &p.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[0].Objects.Consumption.Files[0].CPP.ExpandedSearchMisses[0]
			miss.Protocol, miss.Source = gotoolprofile.CPPPackageSearchMissProtocol, "module/probe_amd64.s"
		},
		"extra unconsumed expanded operand": func(p *discoveryCorpusResult) {
			cpp := &p.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[0].Objects.Consumption.Files[0].CPP
			cpp.ExpandedSearchMisses = append(cpp.ExpandedSearchMisses, cpp.ExpandedSearchMisses[0])
		},
		"baseline-only scopes": func(p *discoveryCorpusResult) {
			p.OrdinarySelectionPlan.InstrumentationPlan.CPPRequirements = nil
			p.OrdinarySelectionPlan.InstrumentationPlan.Outcomes = p.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[:1]
			p.Translations, p.InstrumentationTranslations = 1, 1
		},
		"missing CPP branch scope": func(p *discoveryCorpusResult) {
			proof := p.OrdinarySelectionPlan.InstrumentationPlan
			proof.CPPRequirements = proof.CPPRequirements[:len(proof.CPPRequirements)-1]
			proof.Outcomes = proof.Outcomes[:len(proof.Outcomes)-1]
			p.Translations--
			p.InstrumentationTranslations--
		},
		"lost original CPP": func(p *discoveryCorpusResult) {
			p.OrdinarySelectionPlan.InstrumentationPlan.CPPInputs = nil
		},
		"changed same-mode CPU": func(p *discoveryCorpusResult) {
			p.OrdinarySelectionPlan.InstrumentationPlan.CPPRequirements[0].Overrides["GOAMD64"] = "v1"
		},
		"old denominator protocol": func(p *discoveryCorpusResult) {
			p.OrdinarySelectionPlan.InstrumentationPlan.Protocol = "exact_source_instrumentation_denominator_v2"
		},
		"missing compiler object": func(p *discoveryCorpusResult) {
			p.OrdinarySelectionPlan.InstrumentationPlan.Outcomes[1].Objects = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			mutate(&changed)
			if err := validateOrdinaryProfileResult(changed, []string{"darwin/amd64"}, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatal("incomplete or downgraded CPU union gained candidate pass credit")
			}
		})
	}
}
