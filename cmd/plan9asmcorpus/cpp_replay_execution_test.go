package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

func TestCPPOriginalReplayOrderedDriverDefinitionsFiveActualArchitectures(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), target, nil)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(target, "/")
			file := "pkg/native_" + parts[1] + ".s"
			source := "TEXT ·Probe(SB),4,$0-0\nRET\n" +
				"#define SELECT(P) \\\n#ifdef P \\\nDATA ·value(SB)/4,$ORDER \\\nGLOBL ·value(SB),$4 \\\n#endif \\\n\n" +
				"SELECT(DEFAULT)\nEMPTY\n"
			plan, root, archive := fixtureCPPInputsForTarget(t, target, map[string]string{file: source})
			inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{file}, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
				t.Fatal(err)
			}
			profile := &discoveryAsmCommandProfile{
				Context: ctx, Observed: observed, GoBinary: goBinary,
				GoRoot: runtime.GOROOT(), PackagePath: plan.Module + "/pkg", Environment: targetFeatureTestEnv(),
			}
			binary, args, env, _, err := discoveryAssemblyProfileCommand(profile, parts[0], parts[1], runtime.GOROOT())
			if err != nil {
				t.Fatal(err)
			}
			defines := []string{"ORDER=1", "ORDER=2", "DEFAULT", "EMPTY="}
			for _, definition := range defines {
				args = append(args, "-D", definition)
			}
			object := filepath.Join(t.TempDir(), "original.o")
			args = append(args, "-S", "-o", object, filepath.Join(root, filepath.FromSlash(file)))
			listing, _, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "pkg"), env, binary, args...)
			if err != nil || !strings.Contains(string(listing), "02 00 00 00") {
				t.Fatalf("actual ordered -D overwrite/default/empty object: %v\n%s", err, listing)
			}
			originalSHA, err := discoveryFeatureFileSHA256(object)
			if err != nil {
				t.Fatal(err)
			}
			observation, used, err := replayDiscoveryOriginalCPP(inputs, inputs.Units[0], nil, defines)
			if err != nil || !reflect.DeepEqual(observation.Defines, defines) ||
				!strings.Contains(observation.Output, "$2") || len(used) != 1 {
				t.Fatalf("full original replay differs from actual driver inputs/output: %v\n%s", err, observation.Output)
			}
			canonical, err := json.Marshal(inputs)
			if err != nil {
				t.Fatal(err)
			}
			var restored discoveryCPPInputs
			if err := json.Unmarshal(canonical, &restored); err != nil {
				t.Fatal(err)
			}
			if err := validateDiscoveryCPPInputs(&restored, plan, []string{file}); err != nil {
				t.Fatal(err)
			}
			index := &discoveryCPPPlanningSourceIndex{}
			indexed, indexedUsed, err := replayDiscoveryOriginalCPPWithIndex(&restored, restored.Units[0], nil, defines, index)
			if err != nil || !reflect.DeepEqual(indexed, observation) || !reflect.DeepEqual(indexedUsed, used) {
				t.Fatalf("indexed portable replay differs from actual Go control: %v", err)
			}
			for _, changed := range [][]string{
				{"ORDER=1", "DEFAULT", "EMPTY="}, {"ORDER=2", "ORDER=1", "DEFAULT", "EMPTY="},
				{"ORDER=1", "ORDER=2", "EMPTY="}, {"ORDER=1", "ORDER=2", "DEFAULT", "EMPTY=RET"},
			} {
				other, _, err := replayDiscoveryOriginalCPP(&restored, restored.Units[0], nil, changed)
				if err == nil && other.Output == observation.Output {
					t.Fatalf("independently changed ordered driver inputs silently retained output: %v", changed)
				}
				indexed, indexedUsed, indexedErr := replayDiscoveryOriginalCPPWithIndex(&restored, restored.Units[0], nil, changed, index)
				if err != nil || indexedErr != nil || !reflect.DeepEqual(indexed, other) {
					t.Fatalf("warm lexer index changed the complete ordered driver replay: plain=%v indexed=%v", err, indexedErr)
				}
				if len(indexedUsed) != 1 {
					t.Fatal("warm lexer index changed actual source consumption")
				}
			}
			t.Logf("actual %s %s original_source_sha=%s object_sha=%s full_output_sha=%s",
				observed.GoVersion, target, inputs.Sources["module/"+file].SHA256,
				originalSHA, discoveryFeatureBytesSHA256([]byte(observation.Output)))
		})
	}
}

func TestCPPOriginalReplaySourceOrderAndRawResourceMutations(t *testing.T) {
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": "#include \"sub/outer.h\"\n" +
			"#define INVOKE(P) SELECT(P)\nINVOKE(GOAMD64_v3)\n" +
			"TEXT ·Probe(SB),4,$0-0\nRET\n",
		"pkg/sub/outer.h": "#define SELECT(P) \\\n#ifdef P \\\n#include \"choice.h\" \\\n#else \\\n#include \"alternate.h\" \\\n#endif \\\n\n",
		"pkg/choice.h":    "#define VALUE 3\n", "pkg/alternate.h": "#define VALUE 1\n",
	})
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	for _, defines := range [][]string{{"GOAMD64_v1"}, {"GOAMD64_v3"}} {
		observation, used, err := replayDiscoveryOriginalCPP(inputs, inputs.Units[0], nil, defines)
		if err != nil || len(used) != 3 {
			t.Fatalf("full source-order active resource consumption: %v %v", used, err)
		}
		if _, err := discoveryCPPBranchCoverage(observation); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCPPInputs){
		"delete_inactive_resource": func(copy *discoveryCPPInputs) { delete(copy.Sources, "module/pkg/alternate.h") },
		"delete_generated_edge": func(copy *discoveryCPPInputs) {
			for key, value := range copy.Units[0].Includes {
				if value == "module/pkg/choice.h" {
					delete(copy.Units[0].Includes, key)
				}
			}
		},
		"paired_original_and_hash_change": func(copy *discoveryCPPInputs) {
			text := "#define VALUE 99\n"
			changed, err := discoveryReplayCPPSource("pkg/choice.h", []byte(text))
			if err != nil {
				t.Fatal(err)
			}
			copy.Sources["module/pkg/choice.h"] = changed
		},
	} {
		t.Run(name, func(t *testing.T) {
			var copy discoveryCPPInputs
			if err := json.Unmarshal(encoded, &copy); err != nil {
				t.Fatal(err)
			}
			mutate(&copy)
			if err := verifyDiscoveryCPPModuleZIP(&copy, plan, archive); err == nil {
				t.Fatal("changed raw/source graph was detached from actual original ZIP")
			}
		})
	}
	// The same engine is the authority for token-stack behavior. The raw
	// source graph is not a second conditional/macro executor.
	if _, err := plan9asm.InspectAssemblyCPPDriverDefinitions([]string{"ORDER=1", "ORDER=2"}); err != nil {
		t.Fatal(err)
	}
}
