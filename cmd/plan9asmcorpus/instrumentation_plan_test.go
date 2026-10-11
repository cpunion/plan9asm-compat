package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestInstrumentationDenominatorReplaysCompleteModeCGOAndOriginalPairs(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseline, err := captureDiscoveryTargetFeatures(ctx, binary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, asm, goGuard string
		wantModes          []string
		wantCGO            []string
	}{
		{"complete empty set", "", "", nil, nil},
		{"default CGO1", "race", "race", []string{"race"}, []string{"1"}},
		{"shared assembly mode Go", "", "race", []string{"race"}, []string{"1"}},
		{"mode assembly ordinary Go", "race", "", []string{"race"}, []string{"1"}},
		{"explicit CGO0", "race && !cgo", "race && !cgo", []string{"race"}, []string{"0"}},
		{"both explicit CGO scopes", "race && (cgo || !cgo)", "race", []string{"race", "race"}, []string{"0", "1"}},
		{"exclusive sanitizer modes", "msan || asan", "msan || asan", []string{"asan", "msan"}, []string{"1", "1"}},
		{"no compatible source pair", "race", "!race", nil, nil},
		{"ignored release source", "race && go1.99", "race", nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := &discoveryOrdinarySelectionPlan{
				Module: "example.invalid/modeplan", Version: "v1.0.0", GoVersion: baseline.GoVersion,
				Targets: []string{baseline.Target}, Sources: []ordinarySelectionSource{
					{File: "probe_amd64.s", Header: ordinaryProfileTestHeader(test.asm, "")},
					{File: "probe.go", Header: ordinaryProfileTestHeader(test.goGuard, "package probe\n")},
				},
			}
			if err := captureDiscoveryInstrumentationDenominator(plan, []string{"probe_amd64.s"}, []*discoveryTargetFeatures{baseline}); err != nil {
				t.Fatal(err)
			}
			proof := plan.InstrumentationPlan
			if proof.Requirements == nil || len(proof.Requirements) != len(test.wantModes) {
				t.Fatalf("complete source-derived mode denominator changed: %+v", proof)
			}
			var modes, cgos []string
			for _, r := range proof.Requirements {
				modes, cgos = append(modes, string(r.Mode)), append(cgos, r.CGO)
				if r.Directory != "." || len(r.Tags) != 0 || !reflect.DeepEqual(r.Pairs, [][2]string{{"probe_amd64.s", "probe.go"}}) {
					t.Fatalf("mode was a custom tag or lost its original source pair: %+v", r)
				}
			}
			if !equalDiscoveryStrings(modes, test.wantModes) || !equalDiscoveryStrings(cgos, test.wantCGO) {
				t.Fatalf("mode/CGO source pairing differs: modes=%v CGO=%v", modes, cgos)
			}
			if err := validateDiscoveryInstrumentationDenominator(plan, []string{"probe_amd64.s"}, []*discoveryTargetFeatures{baseline}); err != nil {
				t.Fatal(err)
			}
			plan.InstrumentationPlan = nil
			if err := validateDiscoveryInstrumentationDenominator(plan, []string{"probe_amd64.s"}, []*discoveryTargetFeatures{baseline}); err == nil {
				t.Fatal("missing plan accepted, including the zero-requirement case")
			}
			plan.InstrumentationPlan = &discoveryInstrumentationPlan{Protocol: discoveryInstrumentationPlanProtocol}
			if err := validateDiscoveryInstrumentationDenominator(plan, []string{"probe_amd64.s"}, []*discoveryTargetFeatures{baseline}); err == nil {
				t.Fatal("null denominator treated as independently proven empty set")
			}
		})
	}
}

func TestInstrumentationPreparationFailureRetainsRequiredOutcomes(t *testing.T) {
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "instrumentation"), 0700); err != nil {
		t.Fatal(err)
	}
	plan := &discoveryOrdinarySelectionPlan{InstrumentationPlan: &discoveryInstrumentationPlan{
		Protocol: discoveryInstrumentationPlanProtocol,
		Requirements: []discoveryInstrumentationRequirement{
			{ID: "first", Mode: gotoolprofile.InstrumentationRace},
			{ID: "second", Mode: gotoolprofile.InstrumentationASan},
		},
	}}
	objects, err := runDiscoveryInstrumentation(discoveryCorpusConfig{}, discoveryCandidate{}, moduleDownloadInfo{}, plan, nil, work, nil)
	if err == nil || objects != 0 || len(plan.InstrumentationPlan.Outcomes) != 2 {
		t.Fatal("owned workspace setup failure became an empty denominator or successful object")
	}
	for index, outcome := range plan.InstrumentationPlan.Outcomes {
		if outcome.RequirementID != plan.InstrumentationPlan.Requirements[index].ID || outcome.Status != "failed" || outcome.Stage != "environment" || outcome.Error == "" {
			t.Fatalf("setup failure dropped a required scope: %+v", outcome)
		}
	}
}
