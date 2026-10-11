package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// The synthetic archive identity is only a first-party validation fixture.
// It is never a compiler, archive-membership or external-library receipt.
func cppPortableValidationFixture(t *testing.T, units int) (*discoveryCPPInputs, *discoveryOrdinarySelectionPlan, []string) {
	t.Helper()
	inputs := cppResourceComplexityFixture(t, units)
	inputs.Module = "example.invalid/portable-cpp-validation"
	inputs.Version = "v1.0.0"
	inputs.ModuleSum = "h1:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	inputs.ZipSHA256 = strings.Repeat("a", 64)
	var err error
	inputs.Registration, err = captureDiscoveryCPPRegistration(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	plan := &discoveryOrdinarySelectionPlan{
		Module: inputs.Module, Version: inputs.Version, ModuleSum: inputs.ModuleSum,
		ZipSHA256: inputs.ZipSHA256, GoVersion: runtime.Version(),
	}
	var files []string
	for _, unit := range inputs.Units {
		files = append(files, unit.File)
		source := inputs.Sources["module/"+unit.File]
		plan.Sources = append(plan.Sources, ordinarySelectionSource{File: unit.File, SHA256: source.SHA256})
	}
	data, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	var portable discoveryCPPInputs
	if err := json.Unmarshal(data, &portable); err != nil {
		t.Fatal(err)
	}
	return &portable, plan, files
}

func TestCPPPortableValidationResourcePlanningScalesLinearly(t *testing.T) {
	measure := func(units int) float64 {
		inputs, plan, files := cppPortableValidationFixture(t, units)
		return testing.AllocsPerRun(1, func() {
			if err := validateDiscoveryReplayCPPInputs(inputs, plan, files); err != nil {
				t.Fatal(err)
			}
		})
	}
	small, large := measure(2), measure(16)
	t.Logf("complete portable validation allocations: 2 units=%g; 16 units=%g", small, large)
	// Eight times as many originals permits twelve times as many allocations.
	// All original bytes must still be parsed; per-unit relexing must not
	// multiply that complete lexical work by every other unit.
	if small == 0 || large > 12*small {
		t.Fatalf("portable validation relexed every source for each unit: %g > 12 * %g", large, small)
	}
}

func TestCPPPortableValidationDoesNotPopulateCallerIndices(t *testing.T) {
	inputs, plan, files := cppPortableValidationFixture(t, 2)
	before, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		if err := validateDiscoveryReplayCPPInputs(inputs, plan, files); err != nil {
			t.Fatal(err)
		}
		for _, source := range inputs.Sources {
			if source.resourceIndex != nil {
				t.Fatal("validation populated a shared caller index")
			}
		}
		after, err := json.Marshal(inputs)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("validation mutated the portable source graph: %v", err)
		}
	}
}

func TestCPPPortableValidationRechecksEverySourceProjection(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		mutate func(*discoveryCPPSource)
	}{
		{"original", func(source *discoveryCPPSource) {
			changed := *source.Original + "DATA ·other(SB)/8,$\"new.h\"\n"
			source.Original = &changed
		}},
		{"hash", func(source *discoveryCPPSource) { source.SHA256 = strings.Repeat("0", 64) }},
		{"file", func(source *discoveryCPPSource) { source.File = "other/native.s" }},
		{"directives", func(source *discoveryCPPSource) {
			source.Directives = append(source.Directives, discoveryCPPDirective{Line: 1, Kind: "include", Include: "forged.h"})
		}},
		{"missing_original", func(source *discoveryCPPSource) { source.Original = nil }},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			inputs, plan, files := cppPortableValidationFixture(t, 2)
			if err := validateDiscoveryReplayCPPInputs(inputs, plan, files); err != nil {
				t.Fatal(err)
			}
			id := "module/" + files[0]
			source := inputs.Sources[id]
			// Even a stale private lexer index cannot authenticate changed
			// transport fields or replace a fresh complete-source parse.
			parsed, err := discoveryReplayCPPSource(source.File, []byte(*source.Original))
			if err != nil {
				t.Fatal(err)
			}
			source.resourceIndex = parsed.resourceIndex
			fixture.mutate(&source)
			inputs.Sources[id] = source
			if err := validateDiscoveryReplayCPPInputs(inputs, plan, files); err == nil {
				t.Fatal("prior valid source concealed a changed public projection")
			}
		})
	}
}

func TestCPPPortableValidationConcurrentQueriesRemainIndependent(t *testing.T) {
	inputs, plan, files := cppPortableValidationFixture(t, 2)
	const workers = 4
	results := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			for iteration := 0; iteration < 2; iteration++ {
				if err := validateDiscoveryReplayCPPInputs(inputs, plan, files); err != nil {
					results <- fmt.Errorf("concurrent portable validation: %w", err)
					return
				}
			}
			results <- nil
		}()
	}
	for worker := 0; worker < workers; worker++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	for _, source := range inputs.Sources {
		if source.resourceIndex != nil {
			t.Fatal("concurrent validation published an index into its caller")
		}
	}
}
