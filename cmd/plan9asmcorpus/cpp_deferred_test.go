package main

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestDeferredCPPRawRegistrationKeepsGeneratedAndInactiveIncludes(t *testing.T) {
	plan, root, _ := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": "#include \"go_asm.h\"\n#ifdef GOAMD64_v3\n#include \"missing-v3.h\"\n#endif\n#ifdef ABSENT\n#include \"missing-inactive.h\"\n#endif\nTEXT ·Probe(SB),$0-0\nRET\n",
	})
	inputs, err := captureDiscoveryDeferredCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	unit := inputs.Units[0]
	if inputs.Protocol != discoveryReplayCPPInputsProtocol || len(unit.DeferredIncludes) != 3 || len(inputs.Sources) != 1 || len(unit.Includes) != 0 {
		t.Fatalf("raw inventory erased an unresolved/generated registration or invented source: %#v", inputs)
	}
	if err := validateDiscoveryCPPInputs(inputs, plan, []string{"pkg/native_amd64.s"}); err != nil {
		t.Fatal(err)
	}
	delete(unit.DeferredIncludes, "module/pkg/native_amd64.s#0")
	inputs.Units[0] = unit
	if err := validateDiscoveryCPPInputs(inputs, plan, []string{"pkg/native_amd64.s"}); err == nil {
		t.Fatal("deferred raw registration accepted an omitted generated edge")
	}
}

func TestDeferredCPPProfilesDoNotAssumeUnknownHeaderPresenceAbsent(t *testing.T) {
	plan, root, _ := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": "#include \"go_asm.h\"\n#ifdef const_Optional\n#ifdef GOAMD64_v3\n#endif\n#endif\nTEXT ·Probe(SB),$0-0\nRET\n",
	})
	var err error
	plan.CPPInputs, err = captureDiscoveryDeferredCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	profiles, err := captureDiscoveryFeatureProfiles(ctx, binary, t.TempDir(), targetFeatureTestEnv(), plan, []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	var v3 bool
	for _, profile := range profiles {
		v3 = v3 || profile.Observed.Environment["GOAMD64"] == "v3"
	}
	if !v3 {
		t.Fatal("unknown generated presence erased a latent CPU branch before actual type/header queries")
	}
}

func TestDeferredCPPConsumptionRequiresActualGeneratedPresenceAndActiveBinding(t *testing.T) {
	plan, root, _ := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": "#include \"go_asm.h\"\n#ifdef const_Optional\n#include \"missing-active.h\"\n#endif\nTEXT ·Probe(SB),$0-0\nRET\n",
	})
	inputs, err := captureDiscoveryDeferredCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discoveryDeferredCPPConsumption(inputs, inputs.Units[0], nil, nil); err == nil {
		t.Fatal("missing full header silently became absent generated definitions")
	}
	header := &gotoolprofile.GeneratedHeaderProof{PackagePath: plan.Module + "/pkg", Definitions: map[string]string{"Layout__size": "8"}}
	consumed, err := discoveryDeferredCPPConsumption(inputs, inputs.Units[0], header, nil)
	if err != nil || len(consumed) != 2 || consumed["generated/"+header.PackagePath+"/go_asm.h"] == "" {
		t.Fatalf("source-order absent macro consumed inactive unresolved include: %v: %v", consumed, err)
	}
	header.Definitions["const_Optional"] = "1"
	if _, err := discoveryDeferredCPPConsumption(inputs, inputs.Units[0], header, nil); err == nil {
		t.Fatal("new actual presence silently ignored an active missing include")
	}
}

func TestDeferredCPPRawRegistrationDoesNotEagerlyRejectGuardedIncludeCycles(t *testing.T) {
	plan, root, _ := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": "#include \"guarded.h\"\nTEXT ·Probe(SB),$0-0\nRET\n",
		"pkg/guarded.h":      "#ifndef ONCE\n#define ONCE\n#include \"guarded.h\"\n#endif\n",
	})
	inputs, err := captureDiscoveryDeferredCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatalf("raw registration prematurely treated a source-order guarded cycle as invalid: %v", err)
	}
	if err := validateDiscoveryCPPInputs(inputs, plan, []string{"pkg/native_amd64.s"}); err != nil {
		t.Fatal(err)
	}
}
