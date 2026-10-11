package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCPPConditionsInventoryUsesActualGoDirectiveGrammar(t *testing.T) {
	source := []byte("/* license #ifdef FORGED */\n#define LOCAL(x) MOVQ x, R0 \\\n\tADDQ $1, R0\n#ifdef GOAMD64_v3 // real branch\n#ifndef LOCAL\n#endif\n#else\n#include \"detail.h\"\n#endif\n#undef LOCAL\nTEXT ·Probe(SB),$0-0\nRET\n")
	input, err := discoveryCPPConditionsFromBytes("entry.s", source)
	if err != nil {
		t.Fatal(err)
	}
	var actual []string
	for _, directive := range input.Directives {
		actual = append(actual, directive.Kind+":"+directive.Name+directive.Include)
	}
	want := []string{"define:LOCAL", "ifdef:GOAMD64_v3", "ifndef:LOCAL", "endif:", "else:", "include:detail.h", "endif:", "undef:LOCAL"}
	if !reflect.DeepEqual(actual, want) || input.SHA256 != discoveryFeatureBytesSHA256(source) {
		t.Fatalf("CPP source condition inventory incomplete: %v want %v sha=%s", actual, want, input.SHA256)
	}
}

func TestCPPConditionsGoIdentifierSpellingIsPreserved(t *testing.T) {
	input, err := discoveryCPPConditionsFromBytes("unicode.s", []byte("#define runtime·name 1\n#ifdef runtime·name\n#endif\n#define runtime∕name 1\n#ifndef runtime∕other\n#endif\n"))
	if err != nil || len(input.Directives) != 6 || input.Directives[0].Name != "runtime·name" || input.Directives[3].Name != "runtime∕name" {
		t.Fatalf("CPP identifier namespace differs from actual Go tokenizer: %+v %v", input, err)
	}
}

func TestCPPConditionsInventoryFailsClosedForUnknownGrammar(t *testing.T) {
	for _, source := range []string{
		"#if defined(GOAMD64_v3)\n#endif\n",
		"#ifdef GOAMD64_v3\n#elif GOAMD64_v4\n#endif\n",
		"#include HEADER\n",
		"#ifdef GOAMD64_v3 extra\n#endif\n",
		"#define HIDDEN \\\n#ifdef GOAMD64_v3\n",
		"#define HIDDEN #ifdef GOAMD64_v3\n",
		"#pragma once\n",
	} {
		if _, err := discoveryCPPConditionsFromBytes("bad.s", []byte(source)); err == nil {
			t.Fatalf("unknown/directive-generating macro silently disappeared: %q", source)
		}
	}
	// These large-input bounds are failure conditions, never N/A evidence.
	if _, err := discoveryCPPConditionsFromBytes("large.s", []byte(strings.Repeat("#ifdef A\n", discoveryCPPDirectiveLimit+1))); err == nil {
		t.Fatal("unbounded CPP directives were accepted")
	}
}

func TestCPPConditionsWitnessDoesNotEmbedSourceBodies(t *testing.T) {
	source := []byte("#ifdef GOAMD64_v3\n" + strings.Repeat("MOVQ $123456789, R0\n", 100000) + "#else\nRET\n#endif\n")
	input, err := discoveryCPPConditionsFromBytes("bulk.s", source)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(input)
	if err != nil || len(canonical) > 1024 || len(input.Directives) != 3 || strings.Contains(string(canonical), "123456789") {
		t.Fatalf("condition witness embedded assembly bodies or lost controls: size=%d err=%v", len(canonical), err)
	}
}

func TestCPPConditionsRawInventoryRetainsDirectiveAtFileEOF(t *testing.T) {
	// This is original-source registration, not proof that a translation unit
	// is valid. cmd/asm may obtain the terminating newline from its parent
	// tokenizer; independently observed compilation still decides acceptance.
	for _, source := range []string{
		"#define EMPTY", "#define VALUE 42", "#define F(x) x",
		"#ifdef PRESENT", "#ifndef ABSENT", "#undef PRESENT",
		"#else", "#endif", "#include \"inner.h\"", "#line 337 \"mapped.s\"",
	} {
		input, err := discoveryCPPConditionsFromBytes("header.h", []byte(source))
		if err != nil || len(input.Directives) != 1 || input.SHA256 != discoveryFeatureBytesSHA256([]byte(source)) {
			t.Errorf("complete directive at file EOF lost its original bytes/control: %q %+v %v", source, input, err)
		}
	}
	for _, source := range []string{"#", "#ifdef", "#ifndef 42", "#include", "#line 337", "#unknown"} {
		if _, err := discoveryCPPConditionsFromBytes("invalid.h", []byte(source)); err == nil {
			t.Errorf("incomplete/unknown EOF directive accepted by raw registration: %q", source)
		}
	}
}

func TestCPPInputsHeaderEOFOriginalZIPAndReplay(t *testing.T) {
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/sub/outer.h":    "#ifdef GOARCH_amd64\n#define ACTIVE 1\n#endif",
		"pkg/native_amd64.s": "#include \"sub/outer.h\"\n\n#ifdef ACTIVE\nTEXT ·Probe(SB),$0-0\nRET\n#endif\n",
	})
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	directives, err := discoveryCPPUnitDirectives(inputs, inputs.Units[0], make(map[string]bool))
	if err != nil {
		t.Fatal(err)
	}
	states, err := replayDiscoveryCPPConditions(directives, []string{"GOARCH_amd64"})
	if err != nil || !states[3].OuterActive || !states[3].Then {
		t.Fatalf("EOF source-control replay lost the real active branch: %v %v", states, err)
	}
	data, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	var decoded discoveryCPPInputs
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryCPPInputs(&decoded, plan, files); err != nil {
		t.Fatal(err)
	}
}

func TestCPPConditionsReplayTracksLocalDefinitionsAndNestedPaths(t *testing.T) {
	input, err := discoveryCPPConditionsFromBytes("entry.s", []byte("#ifdef GOAMD64_v3\n#define LOCAL 1\n#else\n#define OTHER 1\n#endif\n#ifdef LOCAL\n#ifndef OTHER\n#endif\n#endif\n#undef LOCAL\n"))
	if err != nil {
		t.Fatal(err)
	}
	states, err := replayDiscoveryCPPConditions(input.Directives, []string{"GOAMD64_v3"})
	if err != nil || !states[0].OuterActive || !states[0].Then || !states[5].Then || !states[6].Then {
		t.Fatalf("local/nested predicate replay differs from definedness semantics: %+v %v", states, err)
	}
	// The final #undef is a real source error when its defining branch is off.
	if _, err := replayDiscoveryCPPConditions(input.Directives, nil); err == nil {
		t.Fatal("undefined active #undef was treated as harmless exclusion")
	}
	for _, source := range []string{"#else\n", "#endif\n", "#ifdef A\n", "#define GOAMD64_v3 1\n"} {
		input, err := discoveryCPPConditionsFromBytes("invalid.s", []byte(source))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := replayDiscoveryCPPConditions(input.Directives, []string{"GOAMD64_v3"}); err == nil {
			t.Fatalf("invalid active CPP controls accepted: %q", source)
		}
	}
}

func TestCPPConditionsReplayMatchesActualGoFiveArchitectureMacros(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ target, key, value, macro string }{
		{"linux/386", "GO386", "softfloat", "GO386_softfloat"},
		{"linux/amd64", "GOAMD64", "v3", "GOAMD64_v3"},
		{"linux/arm", "GOARM", "6", "GOARM_7"},
		{"linux/arm64", "GOARM64", "v8.1", "GOARM64_LSE"},
		{"js/wasm", "GOWASM", "signext", "GOWASM_signext"},
	} {
		t.Run(test.target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), test.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			minor, _ := discoveryGoMinor(observed.GoVersion)
			if test.key == "GOARM64" && minor < 23 {
				test.value = "" // A real absent Go-version registration, not a skip.
			}
			observed, err = captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), test.target, map[string]string{test.key: test.value})
			if err != nil {
				t.Fatal(err)
			}
			proof, err := captureDiscoveryAssemblerMacros(runtime.GOROOT(), observed, "example.invalid/cpp-conditions")
			if err != nil {
				t.Fatal(err)
			}
			// Keep a real text symbol: cmd/nm in the audited toolchains panics
			// on some standalone data-only objects. That is an infrastructure
			// failure, not CPP source exclusion evidence.
			source := fmt.Sprintf("TEXT ·Probe(SB),$0-0\nRET\n#ifdef %s\n#define LOCAL 1\nGLOBL ·thenMarker(SB),0,$8\n#else\n#define OTHER 1\nGLOBL ·elseMarker(SB),0,$8\n#endif\n#ifdef LOCAL\n#ifndef OTHER\nGLOBL ·nestedMarker(SB),0,$8\n#endif\n#endif\n", test.macro)
			input, err := discoveryCPPConditionsFromBytes("probe.s", []byte(source))
			if err != nil {
				t.Fatal(err)
			}
			states, err := replayDiscoveryCPPConditions(input.Directives, proof.Defines)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			file, object := filepath.Join(dir, "probe.s"), filepath.Join(dir, "probe.o")
			writeTestFile(t, file, source)
			profile := &discoveryAsmCommandProfile{Context: ctx, Observed: observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(), PackagePath: proof.PackagePath, Environment: targetFeatureTestEnv()}
			parts := strings.Split(test.target, "/")
			binary, args, env, _, err := discoveryAssemblyProfileCommand(profile, parts[0], parts[1], runtime.GOROOT())
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, "-o", object, file)
			if _, _, err := runDiscoveryMachineCommand(ctx, dir, env, binary, args...); err != nil {
				t.Fatal(err)
			}
			nm, _, err := runDiscoveryMachineCommand(ctx, dir, env, binary, "tool", "nm", object)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(nm), "thenMarker") != states[0].Then || strings.Contains(string(nm), "elseMarker") == states[0].Then || strings.Contains(string(nm), "nestedMarker") != (states[6].OuterActive && states[6].Then) {
				t.Fatalf("actual Go branch symbols differ from CPP condition inventory: states=%v nm=%s", states, nm)
			}
			t.Logf("actual %s %s macro=%s env=%v defines=%v source_sha=%s nm_sha=%s", observed.GoVersion, test.target, test.macro, observed.Environment, proof.Defines, input.SHA256, discoveryFeatureBytesSHA256(nm))
		})
	}
}
