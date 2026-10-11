package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFeatureProfilesRetainFeatureOnlyAssembly(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseline, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := &discoveryOrdinarySelectionPlan{
		Module: "example.invalid/features", GoVersion: baseline.GoVersion,
		Targets: []string{baseline.Target}, Sources: []ordinarySelectionSource{
			{File: "vector_amd64.s", Header: "//go:build amd64.v3 && !amd64.v4\n\n"},
			{File: "vector_amd64.go", Header: "//go:build amd64.v3 && !amd64.v4\n\npackage vector\n"},
		}}
	requests, err := planDiscoveryFeatureProfiles(plan, []string{"vector_amd64.s"}, []*discoveryTargetFeatures{baseline})
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		if request.Target == baseline.Target && request.Overrides["GOAMD64"] == "v3" {
			return
		}
	}
	t.Fatalf("feature-only assembly disappeared into baseline exclusion: %+v", requests)
}

func TestFeatureProfilesProofRejectsMissingAndRelabeledObservations(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseline, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := &discoveryOrdinarySelectionPlan{
		Module: "example.invalid/features", GoVersion: baseline.GoVersion,
		Targets: []string{baseline.Target}, Sources: []ordinarySelectionSource{
			{File: "vector_amd64.s", Header: "//go:build amd64.v3 && goexperiment.fieldtrack\n\n"},
			{File: "vector_amd64.go", Header: "//go:build amd64.v3 && goexperiment.fieldtrack\n\npackage vector\n"},
		}}
	files := []string{"vector_amd64.s"}
	profiles, err := captureDiscoveryFeatureProfiles(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), plan, files)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryFeatureProfiles(plan, files, profiles); err != nil {
		t.Fatalf("actual profiles rejected: %v", err)
	}
	for name, mutation := range map[string]func(*[]discoveryFeatureProfile){
		"legacy/no profile":                  func(p *[]discoveryFeatureProfile) { *p = nil },
		"baseline only loses feature ASM":    func(p *[]discoveryFeatureProfile) { *p = (*p)[:1] },
		"missing baseline":                   func(p *[]discoveryFeatureProfile) { *p = (*p)[1:] },
		"duplicate observation":              func(p *[]discoveryFeatureProfile) { *p = append(*p, (*p)[1]) },
		"wrong profile ID":                   func(p *[]discoveryFeatureProfile) { (*p)[1].ID = strings.Repeat("a", 64) },
		"wrong actual CPU environment":       func(p *[]discoveryFeatureProfile) { (*p)[1].Observed.Environment["GOAMD64"] = "v1" },
		"wrong Go version":                   func(p *[]discoveryFeatureProfile) { (*p)[1].Observed.GoVersion = "go1.99.1" },
		"missing source VERSION identity":    func(p *[]discoveryFeatureProfile) { delete((*p)[1].Observed.ToolSourceSHA256, "VERSION") },
		"unknown builtin made custom":        func(p *[]discoveryFeatureProfile) { (*p)[1].Observed.MarkerSelection["goexperiment.madeup"] = true },
		"missing false namespace member":     func(p *[]discoveryFeatureProfile) { delete((*p)[1].Observed.MarkerSelection, "amd64.v4") },
		"same-named custom feature override": func(p *[]discoveryFeatureProfile) { (*p)[1].Request.Overrides["GOFLAGS"] = "-tags=amd64.v3" },
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(profiles)
			if err != nil {
				t.Fatal(err)
			}
			var changed []discoveryFeatureProfile
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			mutation(&changed)
			if err := validateDiscoveryFeatureProfiles(plan, files, changed); err == nil {
				t.Fatal("accepted incomplete/relabeled source-required profile evidence")
			}
		})
	}
}

func TestFeatureProfilesActualDriverConfirmsSourceRequiredCPUAndExperiment(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, requirements := range []string{"amd64.v3 && !amd64.v4", "goexperiment.fieldtrack", "amd64.v3 && goexperiment.fieldtrack"} {
		t.Run(requirements, func(t *testing.T) {
			baseline, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
			if err != nil {
				t.Fatal(err)
			}
			plan := &discoveryOrdinarySelectionPlan{
				Module: "example.invalid/features", GoVersion: baseline.GoVersion,
				Targets: []string{baseline.Target}, Sources: []ordinarySelectionSource{
					{File: "vector_amd64.s", Header: "//go:build " + requirements + "\n\n"},
					{File: "vector_amd64.go", Header: "//go:build " + requirements + "\n\npackage vector\n"},
				}}
			profiles, err := captureDiscoveryFeatureProfiles(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), plan, []string{"vector_amd64.s"})
			if err != nil {
				t.Fatal(err)
			}
			if len(profiles) != 2 {
				t.Fatalf("missing baseline or source-required actual profile: %+v", profiles)
			}
			selected := false
			for _, profile := range profiles {
				if profile.ID == "" || profile.ID != discoveryFeatureProfileID(profile.Observed) {
					t.Fatal("profile identity is not bound to actual driver observation")
				}
				actual, err := discoveryContextForFeatureProfile(profile.Observed)
				if err != nil {
					t.Fatal(err)
				}
				actual.OpenFile = func(file string) (io.ReadCloser, error) {
					for _, source := range plan.Sources {
						if source.File == filepath.ToSlash(file) {
							return io.NopCloser(strings.NewReader(source.Header)), nil
						}
					}
					return nil, fmt.Errorf("uncaptured file %s", file)
				}
				asmMatches, err := actual.MatchFile(".", "vector_amd64.s")
				if err != nil {
					t.Fatal(err)
				}
				goMatches, err := actual.MatchFile(".", "vector_amd64.go")
				if err != nil {
					t.Fatal(err)
				}
				if profile.Request.Baseline && (asmMatches || goMatches) {
					t.Fatal("baseline falsely selected feature-only source")
				}
				if !profile.Request.Baseline && asmMatches && goMatches {
					selected = true
				}
			}
			if !selected {
				t.Fatal("model proposal was not confirmed by actual driver ToolTags")
			}
		})
	}
}

func TestFeatureProfilesDoNotEnableFeatureNamespacesAsCustom(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseline, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, requirement := range []string{"amd64.v99", "goexperiment.unknown", "race"} {
		plan := &discoveryOrdinarySelectionPlan{
			Module: "example.invalid/features", GoVersion: baseline.GoVersion,
			Targets: []string{baseline.Target}, Sources: []ordinarySelectionSource{
				{File: "vector_amd64.s", Header: "//go:build " + requirement + "\n\n"},
				{File: "vector_amd64.go", Header: "package vector\n"},
			}}
		if _, err := planDiscoveryFeatureProfiles(plan, []string{"vector_amd64.s"}, []*discoveryTargetFeatures{baseline}); err == nil {
			t.Fatalf("unsupported feature requirement became custom or empty baseline exclusion: %s", requirement)
		}
	}
	// Future release tags cannot be enabled as custom -tags either. Their
	// fixed current-Go truth value is independently replayed by MatchFile.
	plan := &discoveryOrdinarySelectionPlan{
		Module: "example.invalid/features", GoVersion: baseline.GoVersion,
		Targets: []string{baseline.Target}, Sources: []ordinarySelectionSource{
			{File: "vector_amd64.s", Header: "//go:build go1.99\n\n"},
			{File: "vector_amd64.go", Header: "package vector\n"},
		}}
	requests, err := planDiscoveryFeatureProfiles(plan, []string{"vector_amd64.s"}, []*discoveryTargetFeatures{baseline})
	if err != nil || len(requests) != 1 || !requests[0].Baseline {
		t.Fatalf("future release namespace was incorrectly enabled: %+v %v", requests, err)
	}
}

func TestFeatureProfilesModelMatchesCapturedCPULevels(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		target string
		key    string
		value  string
	}{
		{"linux/amd64", "GOAMD64", "v4"}, {"linux/386", "GO386", "softfloat"}, {"linux/arm", "GOARM", "6"}, {"js/wasm", "GOWASM", "satconv,signext"},
	} {
		features, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), tc.target, map[string]string{tc.key: tc.value})
		if err != nil {
			t.Fatal(err)
		}
		minor, _ := discoveryGoMinor(features.GoVersion)
		arch := features.Environment["GOARCH"]
		modeled := discoveryModeledCPUFeatures(nil, arch, tc.value, minor)
		var observed []string
		for _, tag := range features.ToolTags {
			if strings.HasPrefix(tag, arch+".") {
				observed = append(observed, tag)
			}
		}
		if !equalDiscoveryStrings(modeled, observed) {
			t.Fatalf("profile planning model differs from actual driver for %+v: %v != %v", tc, modeled, observed)
		}
	}
}

func TestFeatureProfilesBaselineRequestsAreDeduplicated(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseline, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"package vector\n", "//go:build !goexperiment.fieldtrack\n\npackage vector\n", "//go:build ignore && goexperiment.unregistered\n\npackage vector\n"} {
		plan := &discoveryOrdinarySelectionPlan{
			Module: "example.invalid/features", GoVersion: baseline.GoVersion,
			Targets: []string{baseline.Target}, Sources: []ordinarySelectionSource{
				{File: "vector_amd64.s", Header: ""}, {File: "vector_amd64.go", Header: header},
			}}
		requests, err := planDiscoveryFeatureProfiles(plan, []string{"vector_amd64.s"}, []*discoveryTargetFeatures{baseline})
		if err != nil || len(requests) != 1 || !requests[0].Baseline {
			t.Fatalf("baseline duplicated or ignored generator created a required profile: %+v %v", requests, err)
		}
	}
}
