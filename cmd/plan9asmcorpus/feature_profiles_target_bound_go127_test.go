//go:build go1.27

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func featureProfileTargetBudgetFixture(t *testing.T, targets []string, variables int) (*discoveryOrdinarySelectionPlan, []string, []*discoveryTargetFeatures) {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var baselines []*discoveryTargetFeatures
	for _, target := range targets {
		observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), target, nil)
		if err != nil {
			t.Fatal(err)
		}
		baselines = append(baselines, observed)
	}
	// These are independent stock Go 1.27 experiment switches, not custom
	// tags or a fabricated target observation. No package initialization runs.
	experiments := []string{"fieldtrack", "staticlockranking", "heapminimum512kib", "arenas", "cgocheck2", "preemptibleloops", "loopvar"}
	if variables < 1 || variables > len(experiments) {
		t.Fatal("invalid bounded fixture experiment count")
	}
	for _, baseline := range baselines {
		for _, name := range experiments[:variables] {
			if _, present := baseline.MarkerSelection["goexperiment."+name]; !present {
				t.Fatalf("actual target %s does not observe experiment %s", baseline.Target, name)
			}
		}
	}
	plan := &discoveryOrdinarySelectionPlan{Module: "example.invalid/target-profile-budget",
		GoVersion: baselines[0].GoVersion, Targets: append([]string(nil), targets...)}
	var assembly []string
	for mask := 0; mask < 1<<variables; mask++ {
		var clauses []string
		for index, name := range experiments[:variables] {
			clause := "goexperiment." + name
			if mask&(1<<index) == 0 {
				clause = "!" + clause
			}
			clauses = append(clauses, clause)
		}
		base := fmt.Sprintf("variant%03d", mask)
		header := "//go:build " + strings.Join(clauses, " && ") + "\n\n"
		plan.Sources = append(plan.Sources,
			ordinarySelectionSource{File: base + ".s", Header: header},
			ordinarySelectionSource{File: base + ".go", Header: header + "package features\n"})
		assembly = append(assembly, base+".s")
	}
	return plan, assembly, baselines
}

func TestFeatureProfilesBudgetIsPerActualTarget(t *testing.T) {
	targets := []string{"linux/amd64", "darwin/amd64", "windows/amd64"}
	plan, assembly, baselines := featureProfileTargetBudgetFixture(t, targets, 5)
	requests, err := planDiscoveryFeatureProfiles(plan, assembly, baselines)
	if err != nil {
		t.Fatalf("three independently bounded target scopes were rejected as one module scope: %v", err)
	}
	if len(requests) != 96 {
		t.Fatalf("expected all 32 necessary profiles on each target, got %d", len(requests))
	}
	counts := make(map[string]int)
	keys := make(map[string]bool)
	covered := make(map[string]bool)
	for _, request := range requests {
		key := discoveryFeatureRequestKey(request)
		if keys[key] {
			t.Fatal("duplicate actual target/environment request", key)
		}
		keys[key] = true
		counts[request.Target]++
		for _, pair := range request.pairs {
			covered[request.Target+"\x00"+pair[0]] = true
		}
	}
	for _, target := range targets {
		if counts[target] != 32 {
			t.Fatalf("target %s lost its independent profile inventory: %d", target, counts[target])
		}
		for _, file := range assembly {
			if !covered[target+"\x00"+file] {
				t.Fatalf("target %s omitted required assembly %s", target, file)
			}
		}
	}
}

func TestFeatureProfilesBudgetStillBoundsOneTarget(t *testing.T) {
	plan, assembly, baselines := featureProfileTargetBudgetFixture(t, []string{"linux/amd64"}, 7)
	if _, err := planDiscoveryFeatureProfiles(plan, assembly, baselines); err == nil || !strings.Contains(err.Error(), "64") {
		t.Fatalf("one target's 128-profile scope escaped its explicit bound: %v", err)
	}
}

func TestFeatureProfilesBudgetTargetAndCountBoundaries(t *testing.T) {
	for _, targets := range [][]string{nil, {"linux/amd64", "linux/amd64"}, {"linux/riscv64"}, make([]string, 65)} {
		if _, err := newDiscoveryFeatureProfileBudget(targets); err == nil {
			t.Fatalf("invalid or unbounded target matrix accepted: %v", targets)
		}
	}
	budget, err := newDiscoveryFeatureProfileBudget([]string{"linux/amd64", "linux/386"})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/amd64", "linux/386"} {
		for count := 0; count < 64; count++ {
			if err := budget.add(target); err != nil {
				t.Fatalf("target %s rejected its %dth bounded request: %v", target, count+1, err)
			}
		}
		if err := budget.add(target); err == nil || !strings.Contains(err.Error(), target) {
			t.Fatalf("target %s accepted its 65th request or lost the failure scope: %v", target, err)
		}
	}
	if err := budget.add("windows/amd64"); err == nil {
		t.Fatal("an uncaptured target borrowed another target's budget")
	}
}

func TestFeatureProfilesBudgetActualDriverFiveArchitectures(t *testing.T) {
	targets := []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"}
	plan, assembly, _ := featureProfileTargetBudgetFixture(t, targets, 4)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	// One minute per actual target, not a larger production command deadline.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(targets))*time.Minute)
	defer cancel()
	profiles, err := captureDiscoveryFeatureProfiles(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), plan, assembly)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 80 {
		t.Fatalf("actual five-target driver did not retain all 80 source-required profiles: %d", len(profiles))
	}
	if err := validateDiscoveryFeatureProfiles(plan, assembly, profiles, ctx); err != nil {
		t.Fatalf("complete actual target scopes rejected by consumer validation: %v", err)
	}
	counts := make(map[string]int)
	for _, profile := range profiles {
		counts[profile.Observed.Target]++
		for tag, expected := range profile.Request.Expected {
			if observed, present := profile.Observed.MarkerSelection[tag]; !present || observed != expected {
				t.Fatalf("actual %s driver contradicted source-required %s=%t", profile.Observed.Target, tag, expected)
			}
		}
	}
	for _, target := range targets {
		if counts[target] != 16 {
			t.Fatalf("actual target %s has %d profiles, want 16", target, counts[target])
		}
	}
}
