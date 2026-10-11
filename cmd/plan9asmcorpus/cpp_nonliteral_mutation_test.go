package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCPPOriginalStringResourceCandidatesDoNotGrantLiteralAuthority(t *testing.T) {
	const file = "pkg/native_amd64.s"
	source := "#define INCLUDE(file) \\\n#include file \\\n\n" +
		"INCLUDE(\"choice.h\")\nTEXT ·Probe(SB),4,$0-0\nRET\n" +
		"DATA ·unused(SB)/8,$\"nofile.h\"\nGLOBL ·unused(SB),$8\n"
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		file: source, "pkg/choice.h": "GLOBL ·chosen(SB),$8\n",
	})
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{file})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	unresolved := false
	for _, kind := range inputs.Units[0].DeferredIncludes {
		unresolved = unresolved || kind == "unresolved_candidate"
	}
	if !unresolved || inputs.Sources["module/pkg/nofile.h"].Original != nil {
		t.Fatal("ordinary DATA String was made a required source or disappeared")
	}
	for _, directive := range inputs.Sources["module/"+file].Directives {
		if directive.Kind == "include" && directive.Include != "" {
			t.Fatal("formal operand was replaced by a fabricated physical literal")
		}
	}
	if _, _, err := replayDiscoveryOriginalCPP(inputs, inputs.Units[0], nil, nil); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCPPInputs){
		"delete_candidate_edge": func(copy *discoveryCPPInputs) {
			for key, target := range copy.Units[0].Includes {
				if target == "module/pkg/choice.h" {
					delete(copy.Units[0].Includes, key)
				}
			}
		},
		"paired_delete_resource": func(copy *discoveryCPPInputs) {
			delete(copy.Sources, "module/pkg/choice.h")
			for key, target := range copy.Units[0].Includes {
				if target == "module/pkg/choice.h" {
					delete(copy.Units[0].Includes, key)
				}
			}
		},
		"pretend_physical_literal": func(copy *discoveryCPPInputs) {
			for key, target := range copy.Units[0].Includes {
				delete(copy.Units[0].Includes, key)
				copy.Units[0].Includes["module/"+file+"#1"] = target
			}
		},
		"extra_candidate": func(copy *discoveryCPPInputs) {
			copy.Units[0].Includes["module/"+file+"?999"] = "module/pkg/choice.h"
		},
		"delete_unresolved": func(copy *discoveryCPPInputs) { copy.Units[0].DeferredIncludes = nil },
		"downgrade":         func(copy *discoveryCPPInputs) { copy.Protocol = discoveryDeferredCPPInputsProtocol },
		"paired_original_hash": func(copy *discoveryCPPInputs) {
			text := strings.Replace(source, "choice.h", "forged.h", 1)
			changed, err := discoveryReplayCPPSource(file, []byte(text))
			if err != nil {
				t.Fatal(err)
			}
			copy.Sources["module/"+file] = changed
		},
	} {
		t.Run(name, func(t *testing.T) {
			var copy discoveryCPPInputs
			if err := json.Unmarshal(data, &copy); err != nil {
				t.Fatal(err)
			}
			mutate(&copy)
			if err := verifyDiscoveryCPPModuleZIP(&copy, plan, archive); err == nil {
				t.Fatal("deleted, forged or downgraded candidate resource was accepted")
			}
		})
	}
	// The candidate was absent in both fixed search origins. Appearance later
	// must revoke that snapshot, even though the candidate was inactive.
	writeTestFile(t, filepath.Join(root, "pkg/nofile.h"), "#define NEW 1\n")
	if err := verifyDiscoveryCPPInputsUnchanged(inputs, root, runtime.GOROOT()); err == nil {
		t.Fatal("late candidate source appearance retained the old graph")
	}
	if err := os.Remove(filepath.Join(root, "pkg/nofile.h")); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPInputsUnchanged(inputs, root, runtime.GOROOT()); err != nil {
		t.Fatal(err)
	}
}
