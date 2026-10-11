package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCPPConditionsDirectiveGeneratingMacrosMatchActualGo(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm",
	} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			observed, err := captureDiscoveryTargetFeatures(
				ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), target, nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(target, "/")
			for _, style := range []string{"object", "object_alias", "function"} {
				t.Run(style, func(t *testing.T) {
					predicate := "GOARCH_" + parts[1]
					name, invocation := "SELECT", "SELECT"
					prefix := ""
					if style == "object_alias" {
						prefix = "#define INVOKE SELECT\n"
						invocation = "INVOKE"
					} else if style == "function" {
						name = "SELECT(PREDICATE)"
						invocation = "SELECT(" + predicate + ")"
						predicate = "PREDICATE"
					}
					source := prefix + strings.Join([]string{
						"#define " + name + " \\",
						"#ifdef " + predicate + " \\",
						"GLOBL ·thenMarker(SB),$8 \\",
						"#else \\",
						"GLOBL ·elseMarker(SB),$8 \\",
						"#endif \\",
						"",
						"TEXT ·Probe(SB),$0-0",
						"RET",
						invocation,
						"",
					}, "\n")
					root := t.TempDir()
					file, object := filepath.Join(root, "probe.s"), filepath.Join(root, "probe.o")
					writeTestFile(t, file, source)
					profile := &discoveryAsmCommandProfile{
						Context: ctx, Observed: observed, GoBinary: goBinary,
						GoRoot: runtime.GOROOT(), PackagePath: "example.invalid/directive-macros",
						Environment: targetFeatureTestEnv(),
					}
					binary, args, env, _, err := discoveryAssemblyProfileCommand(
						profile, parts[0], parts[1], runtime.GOROOT(),
					)
					if err != nil {
						t.Fatal(err)
					}
					args = append(args, "-o", object, file)
					if _, _, err := runDiscoveryMachineCommand(ctx, root, env, binary, args...); err != nil {
						t.Fatalf("original Go directive macro did not compile: %v", err)
					}
					nm, _, err := runDiscoveryMachineCommand(ctx, root, env, binary, "tool", "nm", object)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(nm), "thenMarker") || strings.Contains(string(nm), "elseMarker") {
						t.Fatalf("actual Go macro selected the wrong branch: %s", nm)
					}
					t.Logf("actual Go %s %s/%s source_sha=%s symbols_sha=%s",
						observed.GoVersion, target, style,
						discoveryFeatureBytesSHA256([]byte(source)), discoveryFeatureBytesSHA256(nm),
					)

					input, err := discoveryReplayCPPSource("probe.s", []byte(source))
					if err != nil {
						t.Fatalf("Go-accepted directive macro has no source registration: %v", err)
					}
					if input.SHA256 != discoveryFeatureBytesSHA256([]byte(source)) {
						t.Fatal("macro registration changed its original source identity")
					}
					canonical, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					var restored discoveryCPPSource
					if err := json.Unmarshal(canonical, &restored); err != nil {
						t.Fatal(err)
					}
					roundtrip, err := json.Marshal(restored)
					if err != nil || string(roundtrip) != string(canonical) {
						t.Fatalf("macro registration did not preserve its full portable record: %v", err)
					}
				})
			}
		})
	}
}

func TestCPPConditionsDirectiveMacroIncludesNeedSourceBinding(t *testing.T) {
	source := strings.Join([]string{
		"#define INCLUDE_CHOICE \\",
		"#include \"choice.h\" \\",
		"",
		"INCLUDE_CHOICE",
		"#ifdef CHOSEN",
		"GLOBL ·includedMarker(SB),$8",
		"#endif",
		"TEXT ·Probe(SB),$0-0",
		"RET",
		"",
	}, "\n")
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": source,
		"pkg/choice.h":       "#define CHOSEN 1\n",
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	observed, err := captureDiscoveryTargetFeatures(
		ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	profile := &discoveryAsmCommandProfile{
		Context: ctx, Observed: observed, GoBinary: goBinary,
		GoRoot: runtime.GOROOT(), PackagePath: "example.invalid/cpp-inputs/pkg",
		Environment: targetFeatureTestEnv(),
	}
	binary, args, env, _, err := discoveryAssemblyProfileCommand(
		profile, "linux", "amd64", runtime.GOROOT(),
	)
	if err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(t.TempDir(), "probe.o")
	args = append(args, "-o", object, "native_amd64.s")
	if _, _, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "pkg"), env, binary, args...); err != nil {
		t.Fatalf("original Go macro-generated include did not compile: %v", err)
	}
	nm, _, err := runDiscoveryMachineCommand(ctx, root, env, binary, "tool", "nm", object)
	if err != nil || !strings.Contains(string(nm), "includedMarker") {
		t.Fatalf("original Go did not consume the actual generated include: %s %v", nm, err)
	}
	t.Logf("actual Go %s macro include source_sha=%s symbols_sha=%s",
		observed.GoVersion, discoveryFeatureBytesSHA256([]byte(source)), discoveryFeatureBytesSHA256(nm),
	)
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatalf("macro-generated literal include lacks its source binding: %v", err)
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	registered := false
	for _, source := range inputs.Sources {
		registered = registered || source.File == "pkg/choice.h"
	}
	if !registered {
		t.Fatal("macro-generated include disappeared from the exact source inventory")
	}
	for _, unit := range inputs.Units {
		for key, target := range unit.Includes {
			if target == "module/pkg/choice.h" {
				delete(unit.Includes, key)
				if err := validateDiscoveryCPPInputs(inputs, plan, files); err == nil {
					t.Fatal("missing generated-include origin was accepted")
				}
				return
			}
		}
	}
	t.Fatal("macro-generated include lacks an independently replayable edge")
}
