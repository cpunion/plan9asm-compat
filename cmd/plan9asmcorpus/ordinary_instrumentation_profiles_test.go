package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrdinaryFeatureProfilesDoNotPairInstrumentationOnlyGo(t *testing.T) {
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
	for _, instrumentation := range []string{"race", "msan", "asan"} {
		t.Run(instrumentation, func(t *testing.T) {
			for _, test := range []struct {
				name      string
				asm       string
				goGuard   string
				partner   bool
				wantV3    bool
				wantPair  bool
				wantError bool
			}{
				{name: "optional instrumentation", goGuard: instrumentation, partner: true},
				{name: "ordinary custom alternative", goGuard: instrumentation + " || accelerate", partner: true, wantPair: true},
				{name: "ordinary negation", goGuard: "!" + instrumentation, wantPair: true},
				{name: "ordinary CPU alternative", goGuard: instrumentation + " || amd64.v3", wantV3: true, wantPair: true},
				{name: "assembly still requires instrumentation", asm: instrumentation, goGuard: "!" + instrumentation, partner: true, wantError: true},
				{name: "only instrumentation ASM and Go", asm: instrumentation, goGuard: instrumentation, wantError: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					plan := &discoveryOrdinarySelectionPlan{
						Module:    "example.invalid/features",
						GoVersion: baseline.GoVersion, Targets: []string{baseline.Target},
						Sources: []ordinarySelectionSource{
							{File: "probe_amd64.s", Header: ordinaryProfileTestHeader(test.asm, "")},
							{File: "optional.go", Header: ordinaryProfileTestHeader(test.goGuard, "package probe\n")},
						},
					}
					if test.partner {
						plan.Sources = append(plan.Sources, ordinarySelectionSource{File: "baseline.go", Header: "package probe\n"})
					}
					requests, err := planDiscoveryFeatureProfiles(plan, []string{"probe_amd64.s"}, []*discoveryTargetFeatures{baseline})
					if test.wantError {
						if err == nil || !strings.Contains(err.Error(), "unsupported feature profile") {
							t.Fatalf("instrumentation-only ASM became ordinary N/A: %+v, %v", requests, err)
						}
						return
					}
					if err != nil {
						t.Fatalf("optional Go instrumentation blocked ordinary assembly: %v", err)
					}
					wantCount := 1
					if test.wantV3 {
						wantCount = 2
					}
					if len(requests) != wantCount {
						t.Fatalf("ordinary CPU profile requirements changed: %+v", requests)
					}
					var optionalPair bool
					for _, request := range requests {
						for _, pair := range request.pairs {
							optionalPair = optionalPair || pair[1] == "optional.go"
						}
					}
					if optionalPair != test.wantPair {
						t.Fatalf("ordinary selectable Go partner was dropped or invented: %+v", requests)
					}
					if test.wantV3 {
						var v3 bool
						for _, request := range requests {
							v3 = v3 || request.Overrides["GOAMD64"] == "v3"
						}
						if !v3 {
							t.Fatal("pruning optional instrumentation lost the ordinary CPU alternative")
						}
					}
				})
			}
		})
	}
}

func ordinaryProfileTestHeader(guard, body string) string {
	if guard == "" {
		return body
	}
	return "//go:build " + guard + "\n\n" + body
}
