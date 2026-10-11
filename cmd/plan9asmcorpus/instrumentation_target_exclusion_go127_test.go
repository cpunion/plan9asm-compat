//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// A registered target refusal is separate scope evidence, not an LLVM object
// or a successful candidate. The old v1 failure stays in its frozen report.
func TestInstrumentationOfficialTargetExclusionActualGo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	candidate := discoveryCandidate{
		Module: "example.invalid/targetrule", Version: "v1.0.0",
		AsmFiles: []string{"probe_arm64.s"},
	}
	download := fixtureProfileModuleDownload(t, candidate, map[string]string{
		"go.mod":        "module example.invalid/targetrule\n\ngo 1.20\n",
		"probe.go":      "//go:build race && alpha\n\npackage targetrule\nfunc Probe(x uint64) uint64\n",
		"probe_arm64.s": "//go:build race && alpha\n\nTEXT ·Probe(SB),$0-16\nMOVD x+0(FP), R0\nMOVD R0, ret+8(FP)\nRET\n",
	})
	plan, profiles, _, _, _, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download,
		[]string{"windows/arm64"}, t.TempDir(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	objects, runErr := runDiscoveryInstrumentation(discoveryCorpusConfig{CandidateTimeout: time.Minute},
		candidate, download, plan, profiles, t.TempDir(), os.Environ())
	if runErr == nil || objects != 0 {
		t.Fatalf("all-excluded zero-object candidate must remain incomplete: objects=%d error=%v", objects, runErr)
	}
	proof := plan.InstrumentationPlan
	if len(proof.Requirements) != 1 || len(proof.Outcomes) != 1 {
		t.Fatal("official refusal deleted its source requirement")
	}
	outcome := proof.Outcomes[0]
	if artifacts := os.Getenv("PLAN9ASM_MODE_SCOPE_ARTIFACTS"); artifacts != "" {
		if err := os.MkdirAll(artifacts, 0700); err != nil {
			t.Fatal(err)
		}
		body, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(artifacts, "original-target-rule.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if outcome.Status != "official_target_excluded" || outcome.Stage != "early_rules" || outcome.Error != "" ||
		outcome.Early != nil || outcome.TargetExclusion == nil || outcome.TargetExclusion.Early.Status != gotoolprofile.InstrumentationOfficialTargetUnsupported ||
		outcome.TargetExclusion.ExitCode != 2 || outcome.TargetExclusion.Stderr != "-race is not supported on windows/arm64\n" ||
		outcome.Objects != nil || outcome.Query != nil || outcome.PackagePlan != nil || outcome.ObservationID != "" {
		t.Fatalf("exact stock-Go target rule did not retain independent zero-object exclusion evidence: status=%s stage=%s error=%s", outcome.Status, outcome.Stage, outcome.Error)
	}
	if err := gotoolprofile.ValidateInstrumentationTargetExclusion(outcome.TargetExclusion, proof.Requirements[0].Tags); err != nil {
		t.Fatal(err)
	}
	early := outcome.TargetExclusion.Early
	if !reflect.DeepEqual(proof.Requirements[0].Tags, []string{"alpha"}) || !strings.Contains(strings.Join(outcome.TargetExclusion.CommandArgs, " "), "-tags=alpha") {
		t.Fatal("original custom-tag requirement was absent from the actual scope command")
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, profiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusFailed,
		Error: runErr.Error(), DiscoveredAsmFiles: candidate.AsmFiles, OrdinarySelectionPlan: plan,
		FeatureProfiles: refs, InstrumentationTargetExclusions: 1}
	if err := validateDiscoveryInstrumentationFailure(result, inventory); err != nil {
		t.Fatal(err)
	}
	testInstrumentationCorpusTransport(t, result, inventory, "windows/arm64")
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"foreign module": func(r *discoveryCorpusResult) { r.Module = "example.invalid/foreign" },
		"count":          func(r *discoveryCorpusResult) { r.InstrumentationTargetExclusions = 0 },
		"requirement target": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.InstrumentationPlan.Requirements[0].Target = "windows/amd64"
		},
		"requirement tags":     func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.InstrumentationPlan.Requirements[0].Tags = nil },
		"full source deletion": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.InstrumentationPlan.Sources = nil },
		"full source replacement": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.InstrumentationPlan.Sources["."].Contents["probe.go"] += "// forged\n"
		},
		"predicate": func(r *discoveryCorpusResult) {
			for index := range r.OrdinarySelectionPlan.Sources {
				source := &r.OrdinarySelectionPlan.Sources[index]
				if source.File == "probe.go" {
					source.Header += "// forged\n"
					source.HeaderSHA256 = discoveryFeatureBytesSHA256([]byte(source.Header))
				}
			}
		},
		"original go.mod": func(r *discoveryCorpusResult) {
			for index := range r.OrdinarySelectionPlan.Sources {
				source := &r.OrdinarySelectionPlan.Sources[index]
				if source.File == "go.mod" {
					source.Header += "// forged\n"
					source.HeaderSHA256 = discoveryFeatureBytesSHA256([]byte(source.Header))
				}
			}
		},
		"zero-object pass": func(r *discoveryCorpusResult) { r.Status = discoveryStatusPassed; r.Error = "" },
		"ordinary NA":      func(r *discoveryCorpusResult) { r.Status = discoveryStatusNotApplicable; r.Error = "" },
		"scope objects":    func(r *discoveryCorpusResult) { r.InstrumentationTranslations = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changedProfiles, err := resolveDiscoveryFeatureProfiles(inventory, changed.FeatureProfiles)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if _, _, err := validateDiscoveryInstrumentationResult(changed, changedProfiles, candidate.AsmFiles); err == nil {
				t.Fatal("changed scope or zero-object completion accepted")
			}
		})
	}
	// Historical v1 refusals remain readable as failures, never an exclusion.
	var historical discoveryCorpusResult
	if err := json.Unmarshal(encoded, &historical); err != nil {
		t.Fatal(err)
	}
	old := historical.OrdinarySelectionPlan.InstrumentationPlan
	old.Protocol, old.Sources = discoveryInstrumentationLegacyProtocol, nil
	old.Outcomes[0].Status = "early_target_rejected"
	old.Outcomes[0].Error = "historical stock-Go early refusal"
	old.Outcomes[0].Early = old.Outcomes[0].TargetExclusion.Early
	old.Outcomes[0].TargetExclusion = nil
	historical.InstrumentationTargetExclusions = 0
	if err := validateDiscoveryInstrumentationFailure(historical, inventory); err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryInstrumentationToolProvenance(historical, discoveryCorpusProvenance{}); err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryInstrumentationToolProvenance(historical, discoveryCorpusProvenance{InstrumentationScopeProtocol: discoveryInstrumentationPlanProtocol}); err == nil {
		t.Fatal("current producer relabeled an untagged historical v1 refusal")
	}
	t.Logf("original stock-Go target rule: target=%s mode=%s CGO=%s exit=%d stderr=%q source-registration=%v driver=%s source-pair=%v; no LLVM objects",
		early.Target, early.Mode, early.CGOEnabled, outcome.TargetExclusion.ExitCode, outcome.TargetExclusion.Stderr,
		early.SourceRules.RegistrationSHA256, early.BaselineFeatures.DriverSHA256, proof.Requirements[0].Pairs)
}

func TestInstrumentationOfficialTargetExclusionPreservesSixEligibleRequirements(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	candidate := discoveryCandidate{Module: "example.invalid/sixrules", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
	mod := "module example.invalid/sixrules\n\ngo 1.20\n"
	download := fixtureProfileModuleDownload(t, candidate, map[string]string{
		"go.mod": mod, "probe.go": "//go:build race\n\npackage sixrules\nfunc Probe()\n",
		"probe.s": "//go:build race\n\nTEXT ·Probe(SB),4,$0-0\nRET\n",
	})
	configurePreCPPFixtureProxy(t, candidate, download, mod)
	targets := []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64"}
	plan, profiles, _, _, _, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, targets, t.TempDir(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	// This intentional missing test-owned translator is an infrastructure F,
	// not a missing source/ABI or a target exclusion. All sibling requirements
	// must survive; no compiled LLVM object is claimed by this fixture.
	objects, runErr := runDiscoveryInstrumentation(discoveryCorpusConfig{CandidateTimeout: time.Minute,
		Translator: filepath.Join(t.TempDir(), "missing-translator")}, candidate, download, plan, profiles, t.TempDir(), os.Environ())
	if runErr == nil || objects != 0 || len(plan.InstrumentationPlan.Requirements) != 6 || len(plan.InstrumentationPlan.Outcomes) != 6 || discoveryInstrumentationTargetExclusions(plan) != 1 {
		t.Fatalf("required six-scope denominator was truncated or failures washed: objects=%d requirements=%d error=%v", objects, len(plan.InstrumentationPlan.Requirements), runErr)
	}
	for index, outcome := range plan.InstrumentationPlan.Outcomes {
		requirement := plan.InstrumentationPlan.Requirements[index]
		if requirement.Target == "windows/arm64" {
			if outcome.Status != discoveryInstrumentationExcludedStatus || outcome.Error != "" {
				t.Fatal("exact official refusal lost")
			}
		} else if outcome.Status != "failed" || outcome.Error == "" || outcome.TargetExclusion != nil {
			t.Fatalf("eligible SDK/export/query failure turned into target exclusion: %s %s", requirement.Target, outcome.Status)
		}
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, profiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusFailed, Error: runErr.Error(),
		DiscoveredAsmFiles: candidate.AsmFiles, OrdinarySelectionPlan: plan, FeatureProfiles: refs, InstrumentationTargetExclusions: 1}
	if err := validateDiscoveryInstrumentationFailure(result, inventory); err != nil {
		t.Fatal(err)
	}
	testInstrumentationCorpusTransportTargets(t, result, inventory, targets)
}
