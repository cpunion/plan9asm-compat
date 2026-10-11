package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCPPProfilesRetainMacroOnlyCPUBranches(t *testing.T) {
	plan, moduleDir, _ := fixtureCPPInputs(t)
	inputs, err := captureDiscoveryCPPInputs(plan, moduleDir, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	profiles, err := captureDiscoveryFeatureProfiles(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), plan, []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	var hasV3 bool
	for _, profile := range profiles {
		if profile.Observed.Environment["GOAMD64"] == "v3" {
			hasV3 = true
		}
	}
	if len(profiles) != 2 || !hasV3 {
		t.Fatalf("CPP-only v3 branch disappeared without build tags: %+v", profiles)
	}
	data, err := json.Marshal(profiles)
	if err != nil {
		t.Fatal(err)
	}
	var replay []discoveryFeatureProfile
	if err := json.Unmarshal(data, &replay); err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryFeatureProfiles(plan, []string{"pkg/native_amd64.s"}, replay); err != nil {
		t.Fatalf("CPP-only actual profile lost its offline JSON replay: %v", err)
	}
	var baselineOnly []discoveryFeatureProfile
	for _, profile := range replay {
		if profile.Request.Baseline {
			baselineOnly = append(baselineOnly, profile)
		}
	}
	if err := validateDiscoveryFeatureProfiles(plan, []string{"pkg/native_amd64.s"}, baselineOnly); err == nil {
		t.Fatal("baseline-only report accepted an unobserved CPP feature branch")
	}
}

func TestCPPProfilesUnknownCPUAndUnboundExperimentRoleFailClosed(t *testing.T) {
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
	for _, macro := range []string{"GOAMD64_v99", "GOEXPERIMENT_fieldtrack"} {
		plan, moduleDir, _ := fixtureCPPInputs(t)
		writeTestFile(t, filepath.Join(moduleDir, "pkg/sub/outer.h"), "#ifdef "+macro+"\n#endif\n")
		inputs, err := captureDiscoveryCPPInputs(plan, moduleDir, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
		if err != nil {
			t.Fatal(err)
		}
		plan.CPPInputs = inputs
		if _, err := planDiscoveryFeatureProfiles(plan, []string{"pkg/native_amd64.s"}, []*discoveryTargetFeatures{baseline}); err == nil {
			t.Fatalf("unknown CPU macro or unbound experiment package role became baseline-only: %s", macro)
		}
	}
}

func TestCPPProfilesMacroLevelsAreNotBuildTagLevels(t *testing.T) {
	plan, moduleDir, _ := fixtureCPPInputs(t)
	writeTestFile(t, filepath.Join(moduleDir, "pkg/sub/outer.h"), "#ifdef GOAMD64_v1\n#endif\n#ifdef GOAMD64_v2\n#endif\n#ifdef GOAMD64_v3\n#endif\n#ifdef GOAMD64_v4\n#endif\n")
	inputs, err := captureDiscoveryCPPInputs(plan, moduleDir, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
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
	requests, err := planDiscoveryFeatureProfiles(plan, []string{"pkg/native_amd64.s"}, []*discoveryTargetFeatures{baseline})
	if err != nil {
		t.Fatal(err)
	}
	levels := make(map[string]bool)
	for _, request := range requests {
		level := request.Overrides["GOAMD64"]
		if level == "" {
			level = baseline.Environment["GOAMD64"]
		}
		levels[level] = true
	}
	if len(levels) != 4 {
		t.Fatalf("exclusive Go macro levels were conflated with cumulative build tags: %v", levels)
	}
	for _, request := range requests {
		if strings.Contains(discoveryFeatureRequestKey(request), "-tags") {
			t.Fatal("CPP-only feature was enabled as a fake custom tag")
		}
	}
}

func TestDiscoveryCandidateCPPProfilesCannotBecomeBaselineNA(t *testing.T) {
	t.Setenv("GOAMD64", "v1")
	t.Setenv("GOEXPERIMENT", "")
	started := time.Now()
	result, err := runFixtureCPPProductionCandidate(t, "TEXT ·Probe(SB),$0-0\nRET\n#ifdef GOAMD64_v3\nGLOBL ·v3Marker(SB),0,$8\n#endif\n")
	if err == nil || !strings.Contains(err.Error(), "-feature-profile=") || !strings.Contains(err.Error(), "exec: no command") {
		t.Fatalf("actual production fixture swallowed the CPP-only profile or called it baseline N/A: result=%+v err=%v", result, err)
	}
	if len(result.SourceNotApplicableItems) != 0 || result.NotApplicable != 0 {
		t.Fatalf("unconsumed actual profiles produced N/A scope credit: %+v", result)
	}
	t.Logf("production own-module CPP capture + actual baseline/v3 driver observations elapsed=%s; absent consumer fails closed: %v", time.Since(started), err)
}

func TestOrdinaryReaderRejectsUnconsumedCPPProfile(t *testing.T) {
	plan, root, _ := fixtureCPPInputs(t)
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
	plan.Decisions, _, err = replayOrdinarySelection(plan, files)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: plan.Module, Version: plan.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: files, ApplicableAsmFiles: files, Translations: 1,
		OrdinarySelectionPlan: plan,
		BuildConfigurations:   []discoveryBuildConfiguration{{Targets: plan.Targets, AsmFiles: files}},
	}
	if err := validateOrdinarySelectionResult(result, plan.Targets, plan.GoVersion); err == nil {
		t.Fatal("ordinary reader gave baseline pass credit to an unconsumed CPP-only profile")
	}
}

func TestCPPProfilesActualDriverAndAsmAgreeFiveArchitectures(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target string
		macro  string
	}{
		{target: "linux/386", macro: "GO386_softfloat"},
		{target: "linux/amd64", macro: "GOAMD64_v3"},
		{target: "linux/arm", macro: "GOARM_7"},
		{target: "linux/arm64", macro: "GOARM64_LSE"},
		{target: "js/wasm", macro: "GOWASM_signext"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			parts := strings.Split(tc.target, "/")
			file := "pkg/native_" + parts[1] + ".s"
			source := fmt.Sprintf("#include \"sub/outer.h\"\n#include \"textflag.h\"\nTEXT ·Probe(SB),$0-0\nRET\n#ifdef %s\nGLOBL ·thenMarker(SB),0,$8\n#else\nGLOBL ·elseMarker(SB),0,$8\n#endif\n", tc.macro)
			plan, moduleDir, archive := fixtureCPPInputsForTarget(t, tc.target, map[string]string{file: source, "pkg/sub/outer.h": "#include \"choice.h\"\n"})
			inputs, err := captureDiscoveryCPPInputs(plan, moduleDir, runtime.GOROOT(), []string{file}, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
				t.Fatal(err)
			}
			plan.CPPInputs = inputs
			profiles, err := captureDiscoveryFeatureProfiles(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), plan, []string{file})
			if err != nil {
				t.Fatal(err)
			}
			minor, _ := discoveryGoMinor(plan.GoVersion)
			want := 2
			if parts[1] == "wasm" || parts[1] == "arm" && minor < 22 || parts[1] == "arm64" && minor < 23 {
				want = 1 // Actual audited registration is absent, not a skip.
			}
			if len(profiles) != want {
				t.Fatalf("missing CPP CPU state or invented unregistered macro: profiles=%d want=%d", len(profiles), want)
			}
			directives, err := discoveryCPPUnitDirectives(inputs, inputs.Units[0], make(map[string]bool))
			if err != nil {
				t.Fatal(err)
			}
			for index, profile := range profiles {
				env := replaceEnv(targetFeatureTestEnv(), profile.Observed.Environment)
				list, _, err := runDiscoveryMachineCommand(ctx, moduleDir, env, goBinary, "list", "-find", "-json", "./pkg")
				if err != nil {
					t.Fatal(err)
				}
				var actual struct {
					ImportPath string
					SFiles     []string
				}
				if err := json.Unmarshal(list, &actual); err != nil || actual.ImportPath != plan.Module+"/pkg" || !equalDiscoveryStrings(actual.SFiles, []string{filepath.Base(file)}) {
					t.Fatalf("actual Go did not select the exact own source/package: %s %v", list, err)
				}
				proof, err := captureDiscoveryAssemblerMacros(runtime.GOROOT(), profile.Observed, actual.ImportPath)
				if err != nil {
					t.Fatal(err)
				}
				states, err := replayDiscoveryCPPConditions(directives, proof.Defines)
				if err != nil {
					t.Fatal(err)
				}
				var then bool
				for directiveIndex, directive := range directives {
					if directive.Name == tc.macro {
						state := states[directiveIndex]
						then = state.OuterActive && state.Then
					}
				}
				commandProfile := &discoveryAsmCommandProfile{Context: ctx, Observed: profile.Observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(), PackagePath: actual.ImportPath, Environment: targetFeatureTestEnv()}
				binary, args, asmEnv, macroSources, err := discoveryAssemblyProfileCommand(commandProfile, parts[0], parts[1], runtime.GOROOT())
				if err != nil {
					t.Fatal(err)
				}
				object := filepath.Join(t.TempDir(), fmt.Sprintf("profile-%d.o", index))
				args = append(args, "-I", filepath.Join(runtime.GOROOT(), "pkg", "include"), "-o", object, filepath.Join(moduleDir, filepath.FromSlash(file)))
				if _, _, err := runDiscoveryMachineCommand(ctx, filepath.Join(moduleDir, "pkg"), asmEnv, binary, args...); err != nil {
					t.Fatal(err)
				}
				nm, _, err := runDiscoveryMachineCommand(ctx, moduleDir, asmEnv, binary, "tool", "nm", object)
				if err != nil {
					t.Fatal(err)
				}
				if err := verifyDiscoveryAssemblyProfileTools(commandProfile, macroSources); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(nm), "thenMarker") != then || strings.Contains(string(nm), "elseMarker") == then {
					t.Fatalf("actual ASM branch differs from profile CPP replay: then=%t nm=%s", then, nm)
				}
				objectSHA, err := discoveryFeatureFileSHA256(object)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("actual %s %s profile=%s package=%s macro=%s then=%t CPP_sources=%d object_SHA=%s nm_SHA=%s", plan.GoVersion, tc.target, profile.ID, actual.ImportPath, tc.macro, then, len(inputs.Sources), objectSHA, discoveryFeatureBytesSHA256(nm))
			}
		})
	}
}

func TestCPPProfilesARM64HighLevelsCannotDisableLSE(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseline, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/arm64", nil)
	if err != nil {
		t.Fatal(err)
	}
	minor, _ := discoveryGoMinor(baseline.GoVersion)
	for _, value := range discoveryCPPFeatureCPUValues("arm64", minor, baseline.Environment["GOARM64"]) {
		if strings.Contains(value, "nolse") {
			t.Fatalf("planner invented an environment actual Go cannot accept: %s", value)
		}
	}
	if minor < 23 {
		if !equalDiscoveryStrings(discoveryCPPFeatureCPUValues("arm64", minor, baseline.Environment["GOARM64"]), []string{""}) {
			t.Fatal("pre-Go1.23 invented an ARM64 CPU profile")
		}
		return // Verify actual version absence rather than Skip.
	}
	plan, moduleDir, _ := fixtureCPPInputsForTarget(t, baseline.Target, map[string]string{
		"pkg/decl.go":     "//go:build arm64.v9.1\n\npackage fixture\n",
		"pkg/sub/outer.h": "#ifdef GOARM64_LSE\n#endif\n",
	})
	files := []string{"pkg/native_arm64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, moduleDir, runtime.GOROOT(), files, ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
	profiles, err := captureDiscoveryFeatureProfiles(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), plan, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("high-level source fabricated a reachable non-LSE variant: %+v", profiles)
	}
	for _, profile := range profiles {
		if profile.Request.Baseline {
			continue
		}
		proof, err := captureDiscoveryAssemblerMacros(runtime.GOROOT(), profile.Observed, plan.Module+"/pkg")
		if err != nil {
			t.Fatal(err)
		}
		if profile.Observed.Environment["GOARM64"] != "v9.1" || !containsTargetFeature(proof.Defines, "GOARM64_LSE") {
			t.Fatalf("actual required high-level source did not imply LSE: %+v %+v", profile, proof)
		}
	}
	if _, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), baseline.Target, map[string]string{"GOARM64": "v9.1,nolse"}); err == nil {
		t.Fatal("actual Go observation accepted the fictitious nolse setting")
	}
}
