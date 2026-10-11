package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTargetFeaturesActualDriverBaseline(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env := targetFeatureTestEnv()
	features, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), env, "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	if features.Environment["GOAMD64"] != "v1" || !containsTargetFeature(features.ToolTags, "amd64.v1") {
		t.Fatalf("baseline target must come from actual Go driver, not host build.Default: %+v", features)
	}
	for _, tag := range features.ToolTags {
		if strings.HasPrefix(tag, "arm64.") {
			t.Fatalf("host ARM64 feature leaked into AMD64 target: %s", tag)
		}
	}
}

func targetFeatureTestEnv() []string {
	return replaceEnv(os.Environ(), map[string]string{
		"GOAMD64": "", "GOARM": "", "GOARM64": "", "GO386": "", "GOWASM": "", "GOEXPERIMENT": "", "GOPROXY": "off", "GOENV": "off",
	})
}

func TestTargetFeaturesActualDriverFiveTargets(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			features, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), target, nil)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(target, "/")
			if features.Protocol != "go_driver_builtin_features_v2" || features.Environment["GOOS"] != parts[0] || features.Environment["GOARCH"] != parts[1] {
				t.Fatalf("missing actual target environment: %+v", features)
			}
			if features.Environment["CGO_ENABLED"] != "0" || features.Environment["GOEXPERIMENT"] != "" {
				t.Fatalf("baseline feature environment was not preserved: %+v", features.Environment)
			}
			for _, tag := range features.ToolTags {
				if !strings.HasPrefix(tag, "goexperiment.") && !strings.HasPrefix(tag, parts[1]+".") {
					t.Fatalf("host/other target feature leaked: %s", tag)
				}
				if !features.MarkerSelection[tag] {
					t.Fatalf("unobserved selected feature %s", tag)
				}
			}
			for _, tag := range discoveryCPUFeatureCandidates() {
				if _, observed := features.MarkerSelection[tag]; !observed {
					t.Fatalf("driver omitted feature marker %s", tag)
				}
			}
			for name, digest := range features.ToolSourceSHA256 {
				if filepath.IsAbs(name) || len(digest) != 64 {
					t.Fatalf("invalid portable tool source identity: %s %s", name, digest)
				}
			}
			if len(features.ToolSourceSHA256) != 3 || len(features.DriverSHA256) != 64 || len(features.MarkerSourceSHA256) != 64 || len(features.DriverSelectionSHA256) != 64 {
				t.Fatalf("incomplete actual driver proof: %+v", features)
			}
			proofJSON, err := json.Marshal(features)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("actual baseline driver proof: %s", proofJSON)
			minor, err := discoveryGoMinor(features.GoVersion)
			if err != nil {
				t.Fatal(err)
			}
			switch parts[1] {
			case "386":
				if !features.MarkerSelection["386.sse2"] || features.MarkerSelection["386.softfloat"] {
					t.Fatal("wrong default GO386 selection")
				}
			case "amd64":
				if !features.MarkerSelection["amd64.v1"] || features.MarkerSelection["amd64.v2"] {
					t.Fatal("wrong default GOAMD64 selection")
				}
			case "arm":
				// Cross-target defaults changed between Go versions. The driver
				// environment, not the host or a presumed constant, is the oracle.
				level, err := strconv.Atoi(strings.Split(features.Environment["GOARM"], ",")[0])
				if err != nil || level < 5 || level > 7 {
					t.Fatalf("invalid actual default GOARM: %q", features.Environment["GOARM"])
				}
				for candidate := 5; candidate <= 7; candidate++ {
					if features.MarkerSelection[fmt.Sprintf("arm.%d", candidate)] != (candidate <= level) {
						t.Fatal("actual default GOARM environment disagrees with marker selection")
					}
				}
			case "arm64":
				if features.MarkerSelection["arm64.v8.0"] != (minor >= 23) || features.MarkerSelection["arm64.v8.1"] {
					t.Fatal("wrong version-specific default GOARM64 selection")
				}
			case "wasm":
				if minor >= 27 && (!features.MarkerSelection["wasm.satconv"] || !features.MarkerSelection["wasm.signext"]) {
					t.Fatal("Go 1.27 WASM default features were not captured")
				}
			}
		})
	}
}

func TestTargetFeaturesActualDriverARM64Profile(t *testing.T) {
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
	minor, err := discoveryGoMinor(baseline.GoVersion)
	if err != nil {
		t.Fatal(err)
	}
	// GOARM64 did not exist before Go 1.23. Test that boundary rather than
	// claiming an unsupported driver observed a feature profile.
	if minor < 23 {
		if baseline.Environment["GOARM64"] != "" {
			t.Fatal("pre-GOARM64 driver unexpectedly reported GOARM64")
		}
		return
	}
	features, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/arm64", map[string]string{"GOARM64": "v9.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"arm64.v9.0", "arm64.v9.1", "arm64.v8.0", "arm64.v8.6"} {
		if !features.MarkerSelection[tag] {
			t.Fatalf("actual v9.1 driver did not select implied feature %s", tag)
		}
	}
	for _, tag := range []string{"arm64.v9.2", "arm64.v8.7"} {
		if features.MarkerSelection[tag] {
			t.Fatalf("actual v9.1 driver selected higher feature %s", tag)
		}
	}
}

func TestTargetFeaturesActualDriverInheritsExplicitEnvironment(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseEnv := replaceEnv(targetFeatureTestEnv(), map[string]string{"GOAMD64": "v2", "GOEXPERIMENT": "fieldtrack"})
	features, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), baseEnv, "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	if features.Environment["GOAMD64"] != "v2" || features.Environment["GOEXPERIMENT"] != "fieldtrack" || !features.MarkerSelection["amd64.v2"] || !features.MarkerSelection["goexperiment.fieldtrack"] {
		t.Fatalf("driver did not preserve actual inherited feature environment: %+v", features)
	}
}

func TestTargetFeaturesActualDriverExplicitProfiles(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		target    string
		overrides map[string]string
		selected  []string
		excluded  []string
	}{
		{"amd64v3", "linux/amd64", map[string]string{"GOAMD64": "v3"}, []string{"amd64.v1", "amd64.v2", "amd64.v3"}, []string{"amd64.v4", "arm64.v8.0"}},
		{"softfloat", "linux/386", map[string]string{"GO386": "softfloat"}, []string{"386.softfloat"}, []string{"386.sse2"}},
		{"arm5", "linux/arm", map[string]string{"GOARM": "5"}, []string{"arm.5"}, []string{"arm.6", "arm.7"}},
		{"experiment", "linux/amd64", map[string]string{"GOEXPERIMENT": "fieldtrack"}, []string{"goexperiment.fieldtrack"}, []string{"goexperiment.arenas"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			features, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), tc.target, tc.overrides)
			if err != nil {
				t.Fatal(err)
			}
			for key, wanted := range tc.overrides {
				if features.Environment[key] != wanted {
					t.Fatalf("actual driver did not preserve %s=%s: %+v", key, wanted, features.Environment)
				}
			}
			for _, tag := range tc.selected {
				if !features.MarkerSelection[tag] || !containsTargetFeature(features.ToolTags, tag) {
					t.Fatalf("explicit profile did not select %s", tag)
				}
			}
			for _, tag := range tc.excluded {
				if features.MarkerSelection[tag] || containsTargetFeature(features.ToolTags, tag) {
					t.Fatalf("explicit profile incorrectly selected %s", tag)
				}
			}
		})
	}
}

func TestTargetFeaturesInvalidProfilesFailClosed(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, override := range []map[string]string{
		{"GOAMD64": "v5"}, {"GOEXPERIMENT": "not_a_real_experiment"}, {"GOARM64": "v8.0"}, {"GOFLAGS": "-tags=amd64.v4"}, {"PATH": "/bad"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", override)
		cancel()
		if err == nil {
			t.Fatalf("invalid feature profile was accepted: %+v", override)
		}
	}
	dir := t.TempDir()
	userFile := filepath.Join(dir, "preserve.txt")
	if err := os.WriteFile(userFile, []byte("user bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureDiscoveryTargetFeatures(context.Background(), goBinary, dir, targetFeatureTestEnv(), "linux/amd64", nil); err == nil {
		t.Fatal("nonempty directory was accepted")
	}
	data, err := os.ReadFile(userFile)
	if err != nil || string(data) != "user bytes" {
		t.Fatal("feature observer modified user file")
	}
}

func TestTargetFeatureNamespacesAreNeverCustomTags(t *testing.T) {
	tags := []string{"amd64.v4", "amd64.v99", "arm64.v9.5", "wasm.future", "s390x.future", "goexperiment.simd", "goexperiment.future", "go1.99", "boringcrypto", "race", "msan", "asan", "ordinary_feature"}
	got := discoveryCustomTagsWithoutFeatures(tags, []build.Context{build.Default})
	if !reflect.DeepEqual(got, []string{"ordinary_feature"}) {
		t.Fatalf("builtin feature namespace became arbitrary -tags: %v", got)
	}
}

func TestTargetFeaturesRegistrationFailsClosed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/internal/buildcfg/cfg.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryFeatureRegistration(data); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ from, to string }{
		{"func toolTags()", "func renamedToolTags()"},
		{"tags := experimentTags()", "tags := []string{\"goexperiment.unknown\"}"},
		{"func gogoarchTags()", "func gogoarchTags(receiver int)"},
		{"\"%s.v%d\"", "\"%s.future%d\""},
	} {
		if !strings.Contains(string(data), mutation.from) {
			t.Fatalf("registration fixture did not contain %s", mutation.from)
		}
		changed := []byte(strings.Replace(string(data), mutation.from, mutation.to, 1))
		if err := validateDiscoveryFeatureRegistration(changed); err == nil {
			t.Fatalf("unknown/missing registration was accepted: %s", mutation.to)
		}
	}
}

func TestTargetFeaturesExperimentFlagsAST(t *testing.T) {
	tags, err := discoveryExperimentFeatureCandidates([]byte("package goexperiment; type Other struct{ NotAnExperiment bool }; type Flags struct { FieldTrack bool; JSONv2 bool }"))
	if err != nil || !reflect.DeepEqual(tags, []string{"goexperiment.fieldtrack", "goexperiment.jsonv2"}) {
		t.Fatalf("actual Flags names were not enumerated: %v %v", tags, err)
	}
	for _, source := range []string{
		"package goexperiment; type Flags struct{ Value int }",
		"package goexperiment; type Flags struct{ Embedded }",
		"package goexperiment; type Flags struct{ A, B bool }",
		"package goexperiment; type Flags struct{ SIMD bool; Simd bool }",
		"package goexperiment; type Flags = bool",
		"package goexperiment; type Flags struct{}",
		"package goexperiment; type Flags struct{ A bool }; type Flags struct{ B bool }",
		"package other; type Flags struct{ A bool }",
	} {
		if _, err := discoveryExperimentFeatureCandidates([]byte(source)); err == nil {
			t.Fatalf("unrecognized experiment registration was accepted: %s", source)
		}
	}
}

func TestTargetFeaturesMarkerCompleteness(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tags := []string{"amd64.v1", "amd64.v2"}
	valid := map[string]interface{}{
		"Dir": dir, "ImportPath": discoveryFeatureMarkerModule, "GoFiles": []string{"base.go", "marker000.go"}, "IgnoredGoFiles": []string{"marker001.go"},
	}
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := decodeDiscoveryFeatureMarkers(data, dir, tags)
	if err != nil || !selection["amd64.v1"] || selection["amd64.v2"] {
		t.Fatalf("invalid driver marker observation: %+v %v", selection, err)
	}
	for _, mutation := range []map[string]interface{}{
		{"IgnoredGoFiles": []string{}},
		{"IgnoredGoFiles": []string{"marker000.go", "marker001.go"}},
		{"GoFiles": []string{"marker000.go"}, "IgnoredGoFiles": []string{"base.go", "marker001.go"}},
		{"ImportPath": "other"}, {"SFiles": []string{"injected.s"}}, {"Error": map[string]string{"Err": "failure"}},
		{"GoFiles": []string{"base.go", "marker000.go", "injected.go"}},
	} {
		copy := make(map[string]interface{})
		for key, value := range valid {
			copy[key] = value
		}
		for key, value := range mutation {
			copy[key] = value
		}
		data, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeDiscoveryFeatureMarkers(data, dir, tags); err == nil {
			t.Fatalf("incomplete/contradictory selection accepted: %+v", mutation)
		}
	}
}

func TestTargetFeaturesMachineCommandSeparatesStderr(t *testing.T) {
	if mode := os.Getenv("PLAN9ASM_FEATURE_MACHINE_HELPER"); mode != "" {
		fmt.Fprintln(os.Stdout, `{"selected":true}`)
		fmt.Fprintln(os.Stderr, "go: downloading example.invalid/notice v1.0.0")
		if mode == "failure" {
			os.Exit(7)
		}
		if mode == "overflow" {
			fmt.Fprint(os.Stderr, strings.Repeat("x", discoveryCommandOutputLimit+1))
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, mode := range []string{"success", "failure", "overflow"} {
		out, stderr, err := runDiscoveryMachineCommand(ctx, t.TempDir(), replaceEnv(os.Environ(), map[string]string{"PLAN9ASM_FEATURE_MACHINE_HELPER": mode}), os.Args[0], "-test.run=^TestTargetFeaturesMachineCommandSeparatesStderr$")
		switch mode {
		case "success":
			var selected map[string]bool
			if err != nil || json.Unmarshal(out, &selected) != nil || !selected["selected"] || !strings.Contains(string(stderr), "downloading") {
				t.Fatalf("machine stdout/stderr were mixed or lost: %s %s %v", out, stderr, err)
			}
		case "failure":
			if err == nil || !strings.Contains(err.Error(), "exit status 7") || !strings.Contains(discoveryCommandDiagnostic(err), "downloading") {
				t.Fatalf("machine failure stderr/exit status was lost: %v", err)
			}
		case "overflow":
			if !errors.Is(err, errDiscoveryCommandOutputExceeded) {
				t.Fatalf("truncated machine output was accepted: %v", err)
			}
		}
	}
}

func TestTargetFeatureMembershipUsesExactNamespaceSpelling(t *testing.T) {
	for _, tags := range [][]string{nil, {}, {"amd64.v1", "goexperiment.fieldtrack"}} {
		if containsTargetFeature(tags, "amd64.v3") || containsTargetFeature(tags, "AMD64.v1") || containsTargetFeature(tags, "fieldtrack") {
			t.Fatalf("feature membership invented an alias or CPU level: %v", tags)
		}
	}
	if !containsTargetFeature([]string{"amd64.v1", "goexperiment.fieldtrack"}, "goexperiment.fieldtrack") {
		t.Fatal("registered exact feature spelling is missing")
	}
}

func TestTargetFeaturesRejectsCrossVersionOrMissingExperimentSource(t *testing.T) {
	for _, mutation := range []string{"wrong-version", "missing-real-flag"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"VERSION", "src/internal/buildcfg/cfg.go", "src/internal/goexperiment/flags.go"} {
				data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "wrong-version" && name == "VERSION" {
					data = []byte("go1.19.1\n")
				}
				if mutation == "missing-real-flag" && strings.HasSuffix(name, "flags.go") {
					data = []byte(strings.Replace(string(data), "FieldTrack", "MadeUpExperiment", 1))
				}
				destination := filepath.Join(root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(destination, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := discoveryBuiltinFeatureCandidates(root, runtime.Version()); err == nil {
				t.Fatalf("actual Go driver could observe an incomplete/cross-version feature denominator: %s", mutation)
			}
		})
	}
}
