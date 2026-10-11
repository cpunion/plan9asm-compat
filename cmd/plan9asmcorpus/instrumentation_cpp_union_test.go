package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This test establishes only the required source/CPP denominator on all five
// architectures. Unsupported instrumentation targets still need their actual
// official early-rule exclusions; a modeled CPU request is never an object.
func TestInstrumentationCPPRequiredCPUUnionFiveArchitectures(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ target, macro string }{
		{"linux/386", "GO386_softfloat"},
		{"darwin/amd64", "GOAMD64_v3"},
		{"linux/arm", "GOARM_7"},
		{"darwin/arm64", "GOARM64_LSE"},
		{"js/wasm", "GOWASM_signext"},
	} {
		t.Run(input.target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			arch := strings.Split(input.target, "/")[1]
			asmFile := "pkg/native_" + arch + ".s"
			sources := map[string]string{
				asmFile:           "//go:build race && !cgo\n\n#include \"sub/outer.h\"\n#include \"textflag.h\"\nTEXT ·Probe(SB),$0-0\nRET\n",
				"pkg/decl.go":     "//go:build race && !cgo\n\npackage fixture\n",
				"pkg/sub/outer.h": fmt.Sprintf("#ifdef %s\n#define BRANCH 1\n#else\n#define BRANCH 0\n#endif\n", input.macro),
			}
			plan, root, zip := fixtureCPPInputsForTarget(t, input.target, sources)
			baseline, err := captureDiscoveryTargetFeatures(ctx, binary, t.TempDir(), targetFeatureTestEnv(), input.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := captureDiscoveryInstrumentationDenominator(plan, []string{asmFile}, []*discoveryTargetFeatures{baseline}); err != nil {
				t.Fatal(err)
			}
			if len(plan.InstrumentationPlan.Requirements) != 1 {
				t.Fatalf("mode source constraints lost their complete exact CGO=0 denominator: %+v", plan.InstrumentationPlan.Requirements)
			}
			inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{asmFile}, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryCPPModuleZIP(inputs, plan, zip); err != nil {
				t.Fatal(err)
			}
			plan.InstrumentationPlan.CPPInputs = inputs
			requirements, err := planDiscoveryInstrumentationCPPRequirements(plan, []*discoveryTargetFeatures{baseline}, []string{asmFile})
			if err != nil {
				t.Fatal(err)
			}
			plan.InstrumentationPlan.CPPRequirements = requirements
			if err := validateDiscoveryInstrumentationCPPUnion(plan, []*discoveryTargetFeatures{baseline}, []string{asmFile}); err != nil {
				t.Fatal(err)
			}
			ordinary := *plan
			ordinary.CPPInputs = inputs
			// Only the custom source mode differs from ordinary planning. Both must
			// enumerate the same exact registered assembler CPU branch-side states.
			mode := &discoveryInstrumentationSelectionModel{Mode: plan.InstrumentationPlan.Requirements[0].Mode, CGO: false}
			model, err := discoveryContextForFeatureProfile(baseline)
			if err != nil {
				t.Fatal(err)
			}
			index, err := newDiscoveryInstrumentationSourceIndex(plan, []string{asmFile})
			if err != nil {
				t.Fatal(err)
			}
			model.OpenFile = index.open
			requests, err := planDiscoveryCPPFeaturePairWithMode(&ordinary, model, baseline, asmFile, "pkg/decl.go", discoveryFeatureProfileRequest{
				Target: input.target, Baseline: true,
			}, mode)
			if err != nil {
				t.Fatal(err)
			}
			// The pair grammar returns additional branch-side profiles only;
			// its initial base request is already in the source denominator.
			if len(requirements) != len(requests) {
				t.Fatalf("additional CPP states disappeared between pair grammar and mode union: %d != %d", len(requirements), len(requests))
			}
			for _, request := range discoveryInstrumentationAllRequirements(plan.InstrumentationPlan) {
				if string(request.Mode) != "race" || request.CGO != "0" || len(request.Tags) != 0 ||
					len(request.Pairs) != 1 || request.Pairs[0] != [2]string{asmFile, "pkg/decl.go"} {
					t.Fatal("mode became an ordinary/custom-tag/other-CGO profile")
				}
			}
			if len(requirements) != 0 {
				encoded, err := json.Marshal(plan)
				if err != nil {
					t.Fatal(err)
				}
				var changed discoveryOrdinarySelectionPlan
				if err := json.Unmarshal(encoded, &changed); err != nil {
					t.Fatal(err)
				}
				changed.InstrumentationPlan.CPPRequirements = nil
				if err := validateDiscoveryInstrumentationCPPUnion(&changed, []*discoveryTargetFeatures{baseline}, []string{asmFile}); err == nil {
					t.Fatal("baseline-only CPU denominator passed independent replay")
				}
			}
		})
	}
}
