package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

func TestDeferredCPPRegistrationConvergesOnMonotonicUnion(t *testing.T) {
	for _, fixture := range []struct {
		name       string
		registered []string
		selected   []string
		union      []string
		stable     bool
	}{
		{name: "shrink", registered: []string{"a.s", "b.s"}, selected: []string{"a.s"}, union: []string{"a.s", "b.s"}, stable: true},
		{name: "grow", registered: []string{"a.s"}, selected: []string{"b.s"}, union: []string{"a.s", "b.s"}},
		{name: "reorder", registered: []string{"a.s", "b.s"}, selected: []string{"b.s", "a.s"}, union: []string{"a.s", "b.s"}, stable: true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			union, stable, err := ordinaryProfileCPPRegistrationUnion(fixture.registered, fixture.selected)
			if err != nil || stable != fixture.stable || !reflect.DeepEqual(union, fixture.union) {
				t.Fatalf("registration union: %v, stable=%v, err=%v", union, stable, err)
			}
		})
	}
	var files []string
	for index := 0; index < 512; index++ {
		files = append(files, fmt.Sprintf("source-%03d.s", index))
	}
	if _, stable, err := ordinaryProfileCPPRegistrationUnion(files, files[:1]); err != nil || !stable {
		t.Fatalf("legal bounded shrink should converge: %v", err)
	}
	if _, _, err := ordinaryProfileCPPRegistrationUnion(files, []string{"new.s"}); err == nil {
		t.Fatal("new CPP roots silently exceeded their source bound")
	}
}

func TestDeferredCPPRegistrationRetainsOriginalRootsAfterEligibilityShrinks(t *testing.T) {
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": "#ifdef GOAMD64_v3\n#endif\nTEXT ·Probe(SB),$0-0\nRET\n",
		"pkg/other.s":        "#ifdef GOAMD64_v4\n#endif\nTEXT ·Other(SB),$0-0\nRET\n",
	})
	candidate := discoveryCandidate{Module: plan.Module, Version: plan.Version, AsmFiles: []string{"pkg/native_amd64.s", "pkg/other.s"}}
	plan, err := captureOrdinarySelectionInputs(candidate, root, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOrdinarySelectionZIP(plan, archive, candidate.Module, candidate.Version, ""); err != nil {
		t.Fatal(err)
	}
	inputs, err := captureDiscoveryDeferredCPPInputs(plan, root, runtime.GOROOT(), candidate.AsmFiles)
	if err != nil {
		t.Fatal(err)
	}
	// Registration is monotonic; only final source selection determines the
	// translation denominator. Original, previously registered roots remain
	// bound to their candidate/source hashes, even if no longer eligible.
	if err := validateDiscoveryCPPInputs(inputs, plan, []string{"pkg/native_amd64.s"}); err != nil {
		t.Fatalf("a retained original root must not force eight non-converging iterations: %v", err)
	}
	if len(inputs.Units) != 2 || inputs.Sources["module/pkg/other.s"].Directives[0].Name != "GOAMD64_v4" {
		t.Fatal("shrinking eligibility erased a previously registered CPU condition")
	}
	encoded, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"legacy exact protocol", "duplicate root", "missing required root", "unregistered candidate root", "Go root"} {
		t.Run(change, func(t *testing.T) {
			var altered discoveryCPPInputs
			if err := json.Unmarshal(encoded, &altered); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "legacy exact protocol":
				altered.Protocol = discoveryCPPInputsProtocol
			case "duplicate root":
				altered.Units[1] = altered.Units[0]
			case "missing required root":
				altered.Units = altered.Units[1:]
			case "unregistered candidate root":
				altered.Units[1].File = "pkg/unregistered.s"
				copy := altered.Sources["module/pkg/other.s"]
				copy.File = "pkg/unregistered.s"
				delete(altered.Sources, "module/pkg/other.s")
				altered.Sources["module/pkg/unregistered.s"] = copy
			case "Go root":
				altered.Units[1].File = "pkg/decl.go"
				copy := altered.Sources["module/pkg/other.s"]
				copy.File = "pkg/decl.go"
				for _, original := range plan.Sources {
					if original.File == copy.File {
						copy.SHA256 = original.SHA256
					}
				}
				delete(altered.Sources, "module/pkg/other.s")
				altered.Sources["module/pkg/decl.go"] = copy
			}
			if err := validateDiscoveryCPPInputs(&altered, plan, []string{"pkg/native_amd64.s"}); err == nil {
				t.Fatal("retained raw registration accepted an unbound/missing/duplicate root or weakened the old protocol")
			}
		})
	}
}
