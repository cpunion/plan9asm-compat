package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAssemblySourceProbeMustUseActualProfileMacros(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ target, key, value, macro string }{
		{"linux/386", "GO386", "softfloat", "GO386_softfloat"},
		{"linux/amd64", "GOAMD64", "v3", "GOAMD64_v3"},
		{"linux/arm", "GOARM", "6", "GOARM_6"},
		{"linux/arm64", "GOARM64", "v8.1", "GOARM64_LSE"},
		{"js/wasm", "GOWASM", "satconv", "GOARCH_wasm"},
	} {
		t.Run(test.target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), test.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			minor, _ := discoveryGoMinor(observed.GoVersion)
			if test.key == "GOARM" && minor < 22 {
				test.macro = "GOARCH_arm" // GOARM macros were absent then.
			}
			if test.key == "GOARM64" && minor < 23 {
				test.value, test.macro = "", "GOARCH_arm64"
			}
			observed, err = captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), test.target, map[string]string{test.key: test.value})
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "probe.s")
			writeTestFile(t, file, "#ifdef "+test.macro+"\nTHIS_IS_NOT_A_GO_INSTRUCTION\n#else\nTEXT ·Probe(SB),$0-0\nRET\n#endif\n")
			parts := strings.Split(test.target, "/")
			profile := &discoveryAsmCommandProfile{Context: ctx, Observed: observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(), PackagePath: "example.invalid/ordinary", Environment: targetFeatureTestEnv()}
			result, err := probeAssemblySourceForTarget(ctx, file, parts[0], parts[1], runtime.GOROOT(), profile)
			if err != nil || result.accepted || !result.conclusive || result.reason == "" {
				t.Fatalf("source check used a different CPP/profile branch from actual cmd/go: %+v %v", result, err)
			}
			blankFile := filepath.Join(t.TempDir(), "blank.s")
			writeTestFile(t, blankFile, "#ifdef "+test.macro+"\nTHIS_IS_NOT_A_GO_INSTRUCTION\n#endif\n")
			noSymbols, err := discoveryAssemblyObjectHasNoSymbols(blankFile, parts[0], parts[1], profile)
			if err != nil || noSymbols {
				t.Fatalf("no-symbol check erased an active source error through wrong CPP/profile: noSymbols=%t err=%v", noSymbols, err)
			}
		})
	}
}

func TestAssemblySourceProfileRoleAndUnknownDriverFailClosed(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", map[string]string{"GOEXPERIMENT": "fieldtrack"})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "role.s")
	writeTestFile(t, file, "#ifdef GOEXPERIMENT_fieldtrack\nTHIS_IS_NOT_A_GO_INSTRUCTION\n#else\nTEXT ·Probe(SB),$0-0\nRET\n#endif\n")
	minor, _ := discoveryGoMinor(observed.GoVersion)
	for _, pkg := range []string{"example.invalid/ordinary", "runtime"} {
		profile := &discoveryAsmCommandProfile{Context: ctx, Observed: observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(), PackagePath: pkg, Environment: targetFeatureTestEnv()}
		result, err := probeAssemblySourceForTarget(ctx, file, "linux", "amd64", runtime.GOROOT(), profile)
		want := pkg == "example.invalid/ordinary" || minor < 22
		if err != nil || !result.conclusive || result.accepted != want {
			t.Fatalf("%s source role applied wrong experiment macro branch: %+v %v", pkg, result, err)
		}
	}
	profile := &discoveryAsmCommandProfile{Context: ctx, Observed: observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(), PackagePath: "example.invalid/ordinary", Environment: targetFeatureTestEnv()}
	observed.DriverSHA256 = strings.Repeat("e", 64)
	if result, err := probeAssemblySourceForTarget(ctx, file, "linux", "amd64", runtime.GOROOT(), profile); err == nil || result.accepted || result.conclusive {
		t.Fatalf("unknown actual driver cannot establish source pass or rejection: %+v %v", result, err)
	}
}

func TestAssemblySourceProfileNoSymbolsHonorsCandidateContext(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	file := filepath.Join(t.TempDir(), "blank.s")
	writeTestFile(t, file, "// This object contains no symbols.\n")
	profile := &discoveryAsmCommandProfile{Context: canceled, Observed: observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(), PackagePath: "example.invalid/ordinary", Environment: targetFeatureTestEnv()}
	if noSymbols, err := discoveryAssemblyObjectHasNoSymbols(file, "linux", "amd64", profile); err == nil || noSymbols {
		t.Fatalf("expired candidate still produced no-symbol evidence: noSymbols=%t err=%v", noSymbols, err)
	}
}
