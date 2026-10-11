package main

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These are bounded planning/selection checks, not LLVM object or runtime
// claims. Contexts remain invocation-local and never alter portable sources.
func TestProfilePlanningContextFiveActualArchitectures(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			captureContext, stopCapture := context.WithTimeout(context.Background(), time.Minute)
			defer stopCapture()
			baseline, err := captureDiscoveryTargetFeatures(captureContext, binary, t.TempDir(), targetFeatureTestEnv(), target, nil)
			if err != nil {
				t.Fatal(err)
			}
			file := "pkg/native_" + strings.Split(target, "/")[1] + ".s"
			plan, root, _ := fixtureCPPInputsForTarget(t, target, map[string]string{
				file: "TEXT ·Probe(SB),4,$0-0\nRET\n",
			})
			inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{file}, captureContext)
			if err != nil {
				t.Fatal(err)
			}
			plan.CPPInputs = inputs
			baselines := []*discoveryTargetFeatures{baseline}
			want, err := planDiscoveryFeatureProfiles(plan, []string{file}, baselines)
			if err != nil || len(want) != 1 {
				t.Fatalf("uncanceled ordinary denominator: %v %v", want, err)
			}
			got, err := planDiscoveryFeatureProfiles(plan, []string{file}, baselines, captureContext)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("live context altered portable source proposals: %v", err)
			}
			if err := captureDiscoveryInstrumentationDenominator(plan, []string{file}, baselines); err != nil {
				t.Fatal(err)
			}
			plan.InstrumentationPlan.CPPInputs = inputs
			for _, expired := range []bool{false, true} {
				operation, cancel := context.WithCancel(context.Background())
				wantError := context.Canceled
				if expired {
					cancel()
					operation, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
					wantError = context.DeadlineExceeded
				}
				cancel()
				if _, err := planDiscoveryFeatureProfiles(plan, []string{file}, baselines, operation); !errors.Is(err, wantError) {
					t.Fatalf("ordinary CPU planning hid cancellation/expiry: %v", err)
				}
				if _, err := planDiscoveryInstrumentationCPPRequirements(plan, baselines, []string{file}, operation); !errors.Is(err, wantError) {
					t.Fatalf("instrumentation CPU planning hid cancellation/expiry: %v", err)
				}
			}
			model, err := discoveryContextForFeatureProfile(baseline)
			if err != nil {
				t.Fatal(err)
			}
			index, err := newDiscoveryInstrumentationSourceIndex(plan, []string{file})
			if err != nil {
				t.Fatal(err)
			}
			operation, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			model.OpenFile = func(name string) (io.ReadCloser, error) {
				reads++
				reader, err := index.open(name)
				if reads == 1 {
					cancel()
				}
				return reader, err
			}
			_, err = planDiscoveryCPPFeaturePair(plan, model, baseline, file, "pkg/decl.go",
				discoveryFeatureProfileRequest{Target: target, Baseline: true}, operation)
			if !errors.Is(err, context.Canceled) || reads == 0 || reads > 2 {
				t.Fatalf("CPP CPU loop continued after actual source read canceled it: reads=%d error=%v", reads, err)
			}
		})
	}
}

func TestProfilePlanningContextRejectsAmbiguousInvocations(t *testing.T) {
	for _, contexts := range [][]context.Context{
		{nil}, {context.Background(), context.Background()},
	} {
		if err := checkDiscoveryProfilePlanningContext(contexts); err == nil {
			t.Fatal("ambiguous/nil producer contexts silently became unbounded planning")
		}
	}
	if err := checkDiscoveryProfilePlanningContext(nil); err != nil {
		t.Fatalf("deterministic offline source replay requires no live context: %v", err)
	}
}
