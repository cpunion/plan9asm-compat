package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestCPPHeaderPlanningQueryOwnPackageTags(t *testing.T) {
	candidate := discoveryCandidate{
		Module: "example.invalid/querytags", Version: "v1.0.0",
		AsmFiles: []string{"first/peer_amd64.s", "first/probe_amd64.s", "second/probe_amd64.s"},
	}
	sources := map[string]string{
		"go.mod":                "module example.invalid/querytags\ngo 1.20\n",
		"first/probe.go":        "package first\nfunc Probe()\nfunc Peer()\n",
		"first/alpha.go":        "//go:build alpha\n\npackage first\nconst Alpha = 1\n",
		"first/beta.go":         "//go:build beta\n\npackage first\nconst Beta = 2\n",
		"first/peer_amd64.s":    "TEXT ·Peer(SB),4,$0-0\nRET\n",
		"first/probe_amd64.s":   "TEXT ·Probe(SB),4,$0-0\nRET\n",
		"second/probe.go":       "package second\nfunc Probe()\n",
		"second/combination.go": "//go:build alpha && beta\n\npackage second\nconst Combined = 3\n",
		"second/probe_amd64.s":  "TEXT ·Probe(SB),4,$0-0\nRET\n",
	}
	data, err := os.ReadFile("testdata/go127_feature_protocol_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture featureProtocolFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"darwin/amd64", "linux/amd64"} {
		plan := fixtureOrdinarySelectionForCandidate(t, candidate, []string{target}, sources)
		observed := fixture.Observed[target]
		if observed == nil {
			t.Fatalf("portable source replay lacks an actual profile fixture for %s", target)
		}
		profile := discoveryFeatureProfile{ID: discoveryFeatureProfileID(observed), Observed: observed,
			Request: discoveryFeatureProfileRequest{Target: target, Baseline: true}}
		before, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		for _, tags := range [][]string{nil, {"alpha"}, {"beta"}, {"alpha", "beta"}} {
			t.Run(target+"/tags="+strings.Join(tags, "+"), func(t *testing.T) {
				query, err := discoveryHeaderQuerySourcePlan(plan, profile, "first/probe_amd64.s", tags)
				if err != nil {
					t.Fatal(err)
				}
				input := ordinaryProfileConsumerInput(query, profile, candidate.Module, "", []string{"first/probe_amd64.s"}, tags)
				wanted := []string{"first/peer_amd64.s", "first/probe_amd64.s"}
				if !reflect.DeepEqual(input.RegisteredAsmFiles, wanted) {
					t.Fatalf("query tags %q lost complete selected sibling registration: got=%#v want=%q", tags, input.RegisteredAsmFiles, wanted)
				}
				wire, err := gotoolprofile.MarshalConsumerInput(input)
				if err != nil {
					t.Fatal(err)
				}
				child, err := gotoolprofile.DecodeConsumerInput(bytes.NewReader(wire))
				if err != nil || !reflect.DeepEqual(child.RegisteredAsmFiles, input.RegisteredAsmFiles) {
					t.Fatalf("parent and child query disagree on complete registration: %v", err)
				}
				if len(tags) != 0 && len(ordinaryProfilePackageAssembly(query, profile, []string{"second/probe_amd64.s"}, tags)) != 0 {
					t.Fatal("metadata query propagated custom tags into an unrelated package")
				}
			})
		}
		reverse, err := discoveryHeaderQuerySourcePlan(plan, profile, "second/probe_amd64.s", []string{"alpha", "beta"})
		if err != nil {
			t.Fatal(err)
		}
		if got := ordinaryProfilePackageAssembly(reverse, profile, []string{"second/probe_amd64.s"}, []string{"alpha", "beta"}); !reflect.DeepEqual(got, []string{"second/probe_amd64.s"}) {
			t.Fatalf("second package lost its own complete query scope: %q", got)
		}
		if len(ordinaryProfilePackageAssembly(reverse, profile, []string{"first/probe_amd64.s"}, []string{"alpha", "beta"})) != 0 {
			t.Fatal("second query borrowed or changed the first package's tag registration")
		}
		for _, tags := range [][]string{{""}, {"alpha", "alpha"}, {"beta", "alpha"}, {"alpha && beta"}, {"race"}, {"amd64.v3"}, {"go1.27"}} {
			if _, err := discoveryHeaderQuerySourcePlan(plan, profile, "first/probe_amd64.s", tags); err == nil {
				t.Fatalf("invalid custom tag scope acquired an ordinary query: %q", tags)
			}
		}
		for _, name := range []string{"missing_amd64.s", "first/../first/probe_amd64.s", "first/probe.go"} {
			if _, err := discoveryHeaderQuerySourcePlan(plan, profile, name, nil); err == nil {
				t.Fatalf("unregistered source acquired an ordinary query: %q", name)
			}
		}
		conditionalSources := make(map[string]string)
		for name, contents := range sources {
			conditionalSources[name] = contents
		}
		conditionalSources["first/probe_amd64.s"] = "//go:build alpha && beta\n\n" + sources["first/probe_amd64.s"]
		conditionalSources["first/peer_amd64.s"] = "//go:build !beta\n\n" + sources["first/peer_amd64.s"]
		conditional := fixtureOrdinarySelectionForCandidate(t, candidate, []string{target}, conditionalSources)
		for _, tags := range [][]string{nil, {"alpha"}, {"beta"}} {
			if _, err := discoveryHeaderQuerySourcePlan(conditional, profile, "first/probe_amd64.s", tags); err == nil {
				t.Fatalf("a different viable tag profile authorized this inactive query: %q", tags)
			}
		}
		selected, err := discoveryHeaderQuerySourcePlan(conditional, profile, "first/probe_amd64.s", []string{"alpha", "beta"})
		if err != nil {
			t.Fatal(err)
		}
		if got := ordinaryProfilePackageAssembly(selected, profile, []string{"first/probe_amd64.s"}, []string{"alpha", "beta"}); !reflect.DeepEqual(got, []string{"first/probe_amd64.s"}) {
			t.Fatalf("inactive sibling leaked from another complete package/tag scope: %q", got)
		}
		after, err := json.Marshal(plan)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("private planning query mutated final execution scopes: %v", err)
		}
	}
}
