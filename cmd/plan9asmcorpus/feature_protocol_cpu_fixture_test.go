package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type featureProtocolCPUVariant struct {
	Target         string                     `json:"target"`
	Overrides      map[string]string          `json:"overrides"`
	ObservedPatch  map[string]json.RawMessage `json:"observed_patch"`
	MacrosPatch    map[string]json.RawMessage `json:"macros_patch"`
	ObservedSHA256 string                     `json:"observed_sha256"`
	MacrosSHA256   string                     `json:"macros_sha256"`
}

// These deltas reconstruct actual Go 1.27 captures, not modeled observations.
// Only objects/signatures in the portable accounting fixture are synthetic.
// Full captures remain separate ignored evidence; SDK/tool registration maps
// are shared with the existing baseline rather than duplicated per variant.
func fixtureProfileCPUProposals(t *testing.T, base featureProtocolFixture, requests []discoveryFeatureProfileRequest) ([]discoveryFeatureProfile, map[string]*gotoolprofile.AssemblerMacros) {
	t.Helper()
	data, err := os.ReadFile("testdata/go127_feature_cpu_variants.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Protocol       string                      `json:"protocol"`
		BaselineSHA256 string                      `json:"baseline_sha256"`
		Variants       []featureProtocolCPUVariant `json:"variants"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile("testdata/go127_feature_protocol_fixture.json")
	if err != nil || fixture.Protocol != "actual_go127_portable_fixture_cpu_deltas_v1" ||
		discoveryFeatureBytesSHA256(baseline) != fixture.BaselineSHA256 {
		t.Fatalf("actual CPU captures differ from their shared baseline: %v", err)
	}
	variants := make(map[string]featureProtocolCPUVariant)
	for _, variant := range fixture.Variants {
		key := discoveryFeatureRequestKey(discoveryFeatureProfileRequest{Target: variant.Target, Overrides: variant.Overrides})
		if _, duplicate := variants[key]; duplicate {
			t.Fatal("duplicate actual CPU capture")
		}
		variants[key] = variant
	}
	var profiles []discoveryFeatureProfile
	macros := make(map[string]*gotoolprofile.AssemblerMacros)
	for _, request := range requests {
		observed, registered := base.Observed[request.Target], base.Macros[request.Target]
		if observed == nil || registered == nil || len(request.Expected) != 0 {
			t.Fatal("fixture lacks an actual requested target/experiment capture")
		}
		if !request.Baseline {
			variant, found := variants[discoveryFeatureRequestKey(request)]
			if !found {
				t.Fatalf("fixture omitted a source-required actual CPU capture: %+v", request)
			}
			var next gotoolprofile.Observation
			var nextMacros gotoolprofile.AssemblerMacros
			fixtureCPUCaptureDelta(t, observed, variant.ObservedPatch, variant.ObservedSHA256, &next)
			fixtureCPUCaptureDelta(t, registered, variant.MacrosPatch, variant.MacrosSHA256, &nextMacros)
			observed, registered = &next, &nextMacros
		}
		if err := gotoolprofile.Validate(observed); err != nil {
			t.Fatal(err)
		}
		if err := gotoolprofile.ValidateOrdinaryAssemblerMacros(registered, observed, registered.PackagePath); err != nil {
			t.Fatal(err)
		}
		for key, value := range request.Overrides {
			if observed.Environment[key] != value {
				t.Fatal("actual CPU capture changed its requested environment")
			}
		}
		id := discoveryFeatureProfileID(observed)
		profiles = append(profiles, discoveryFeatureProfile{ID: id, Request: request, Observed: observed})
		macros[id] = registered
	}
	return profiles, macros
}

func fixtureCPUCaptureDelta(t *testing.T, baseline any, patch map[string]json.RawMessage, digest string, output any) {
	t.Helper()
	encoded, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for key, value := range patch {
		if _, known := fields[key]; !known {
			t.Fatalf("CPU capture introduced an unknown field: %s", key)
		}
		fields[key] = value
	}
	encoded, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		t.Fatal(err)
	}
	complete, err := json.Marshal(output)
	if err != nil || discoveryFeatureBytesSHA256(complete) != digest {
		t.Fatalf("CPU delta did not reconstruct the complete actual capture: %v", err)
	}
	var roundTrip any
	if err := json.Unmarshal(complete, &roundTrip); err != nil {
		t.Fatal(err)
	}
	var patched any
	if err := json.Unmarshal(encoded, &patched); err != nil || !reflect.DeepEqual(roundTrip, patched) {
		t.Fatalf("CPU delta lost actual captured fields: %v", err)
	}
}
