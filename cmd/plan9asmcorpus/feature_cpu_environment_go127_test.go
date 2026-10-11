//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type featureCPUEnvironmentTarget struct {
	target    string
	key       string
	inherited string
	override  string
}

var featureCPUEnvironmentTargets = []featureCPUEnvironmentTarget{
	{"linux/386", "GO386", "softfloat", "sse2"},
	{"linux/amd64", "GOAMD64", "v2", "v3"},
	{"linux/arm", "GOARM", "5,softfloat", "7,hardfloat"},
	{"linux/arm64", "GOARM64", "v8.0", "v8.1,lse"},
	{"js/wasm", "GOWASM", "signext", "satconv,signext"},
}

func TestFeatureObserverInactiveCPUEnvironment386(t *testing.T) {
	testFeatureObserverInactiveCPUEnvironment(t, featureCPUEnvironmentTargets[0])
}

func TestFeatureObserverInactiveCPUEnvironmentAMD64(t *testing.T) {
	testFeatureObserverInactiveCPUEnvironment(t, featureCPUEnvironmentTargets[1])
}

func TestFeatureObserverInactiveCPUEnvironmentARM(t *testing.T) {
	testFeatureObserverInactiveCPUEnvironment(t, featureCPUEnvironmentTargets[2])
}

func TestFeatureObserverInactiveCPUEnvironmentARM64(t *testing.T) {
	testFeatureObserverInactiveCPUEnvironment(t, featureCPUEnvironmentTargets[3])
}

func TestFeatureObserverInactiveCPUEnvironmentWASM(t *testing.T) {
	testFeatureObserverInactiveCPUEnvironment(t, featureCPUEnvironmentTargets[4])
}

func testFeatureObserverInactiveCPUEnvironment(t *testing.T, target featureCPUEnvironmentTarget) {
	t.Helper()
	for _, inactive := range featureCPUEnvironmentTargets {
		if inactive.key == target.key {
			continue
		}
		for _, route := range []string{"capture", "cache"} {
			t.Run(inactive.key+"/"+route, func(t *testing.T) {
				env := featureCPUEnvironmentPollutedBase()
				env = replaceEnv(env, map[string]string{inactive.key: inactive.inherited})
				before := append([]string(nil), env...)
				observed := captureFeatureCPUEnvironment(t, route, target.target, env, nil)
				if !reflect.DeepEqual(before, env) {
					t.Fatal("feature observer mutated its caller's original environment")
				}
				if observed.Environment[inactive.key] != "" {
					t.Fatalf("non-target CPU setting became target evidence: %s=%q", inactive.key, observed.Environment[inactive.key])
				}
			})
		}
	}
}

func TestFeatureObserverActiveCPUEnvironmentPreserved(t *testing.T) {
	for _, target := range featureCPUEnvironmentTargets {
		for _, route := range []string{"capture", "cache"} {
			for _, explicit := range []bool{false, true} {
				name := "inherited"
				if explicit {
					name = "override"
				}
				t.Run(target.target+"/"+route+"/"+name, func(t *testing.T) {
					env := replaceEnv(featureCPUEnvironmentPollutedBase(), map[string]string{
						target.key: target.inherited, "GOEXPERIMENT": "fieldtrack",
					})
					wanted := target.inherited
					var overrides map[string]string
					if explicit {
						wanted = target.override
						overrides = map[string]string{target.key: wanted, "GOEXPERIMENT": "fieldtrack"}
					}
					before := append([]string(nil), env...)
					observed := captureFeatureCPUEnvironment(t, route, target.target, env, overrides)
					if !reflect.DeepEqual(before, env) || observed.Environment[target.key] != wanted {
						t.Fatalf("active CPU inheritance/override changed: wanted %s=%q, observed %#v", target.key, wanted, observed.Environment)
					}
					if observed.Environment["GOEXPERIMENT"] != "fieldtrack" || !observed.MarkerSelection["goexperiment.fieldtrack"] {
						t.Fatal("target environment construction lost the actual experiment setting or marker")
					}
				})
			}
		}
	}
}

func TestFeatureObserverForeignCPUOverridesRemainRejected(t *testing.T) {
	binary := featureCPUEnvironmentGoBinary(t)
	for _, target := range featureCPUEnvironmentTargets {
		for _, inactive := range featureCPUEnvironmentTargets {
			if inactive.key == target.key {
				continue
			}
			for _, route := range []string{"capture", "cache"} {
				t.Run(target.target+"/"+inactive.key+"/"+route, func(t *testing.T) {
					ctx, cancel := featureCPUEnvironmentTestContext(t)
					defer cancel()
					env := featureCPUEnvironmentPollutedBase()
					overrides := map[string]string{inactive.key: inactive.inherited}
					var observed *discoveryTargetFeatures
					var err error
					if route == "capture" {
						observed, err = gotoolprofile.Capture(ctx, binary, t.TempDir(), env, target.target, overrides, runDiscoveryMachineCommand)
					} else {
						cache := &discoveryFeatureObservationCache{}
						observed, err = cache.observe(ctx, binary, t.TempDir(), env, target.target, overrides)
					}
					if err == nil || observed != nil || !strings.Contains(err.Error(), "cannot override "+inactive.key) {
						t.Fatalf("explicit foreign CPU request was normalized into permission: observed=%#v err=%v", observed, err)
					}
				})
			}
		}
	}
}

// Keep the original host contamination. In particular, this must not call
// targetFeatureTestEnv, whose clean CPU settings concealed the production bug.
func featureCPUEnvironmentPollutedBase() []string {
	return replaceEnv(os.Environ(), map[string]string{
		"GOARM64": "v8.0", "GOENV": "off", "GOPROXY": "off", "GOTOOLCHAIN": "local",
	})
}

func featureCPUEnvironmentGoBinary(t *testing.T) string {
	t.Helper()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	return binary
}

func captureFeatureCPUEnvironment(t *testing.T, route, target string, env []string, overrides map[string]string) *discoveryTargetFeatures {
	t.Helper()
	logFeatureCPUEnvironment(t, "FEATURE_CPU_ENV_BASE", map[string]any{
		"route": route, "target": target, "environment": featureCPUEnvironmentRoute(env), "overrides": overrides,
	})
	if featureCPUEnvironmentRoute(env)["GOARM64"] != "v8.0" {
		t.Fatal("original GOARM64=v8.0 host contamination was removed from the fixture")
	}
	ctx, cancel := featureCPUEnvironmentTestContext(t)
	defer cancel()
	binary := featureCPUEnvironmentGoBinary(t)
	var actualQueries []map[string]string
	run := func(ctx context.Context, dir string, childEnv []string, name string, args ...string) ([]byte, []byte, error) {
		stdout, stderr, err := runDiscoveryMachineCommand(ctx, dir, childEnv, name, args...)
		wanted := append([]string{"env", "-json"}, discoveryFeatureEnvKeys...)
		if reflect.DeepEqual(args, wanted) {
			commandError := ""
			if err != nil {
				commandError = err.Error()
			}
			logFeatureCPUEnvironment(t, "FEATURE_CPU_ENV_QUERY", map[string]any{
				"route": route, "target": target, "executable": name, "cwd": dir,
				"args": args, "environment": featureCPUEnvironmentRoute(childEnv),
				"stdout": string(stdout), "stderr": string(stderr), "error": commandError,
			})
			var actual map[string]string
			if err == nil && json.Unmarshal(stdout, &actual) == nil {
				actualQueries = append(actualQueries, actual)
			}
		}
		return stdout, stderr, err
	}
	var observed *discoveryTargetFeatures
	var err error
	if route == "capture" {
		observed, err = gotoolprofile.Capture(ctx, binary, t.TempDir(), env, target, overrides, run)
	} else {
		cache := &discoveryFeatureObservationCache{}
		cache.capture = func(ctx context.Context, binary, dir string, env []string, target string, overrides map[string]string) (*discoveryTargetFeatures, error) {
			return gotoolprofile.Capture(ctx, binary, dir, env, target, overrides, run)
		}
		cache.inspect = func(ctx context.Context, binary string, env []string, target string, overrides map[string]string) (*discoveryFeatureDriverState, error) {
			state, err := inspectDiscoveryFeatureDriver(ctx, binary, env, target, overrides)
			if err == nil {
				logFeatureCPUEnvironment(t, "FEATURE_CPU_CACHE_INSPECTION", map[string]any{
					"target": target, "actual_environment": state.environment,
				})
			}
			return state, err
		}
		ownedDir := t.TempDir()
		observed, err = cache.observe(ctx, binary, ownedDir, env, target, overrides)
		if err == nil {
			repeated, repeatErr := cache.observe(ctx, binary, ownedDir, env, target, overrides)
			if repeatErr != nil || !reflect.DeepEqual(observed, repeated) {
				t.Fatalf("same target/cache original inputs did not preserve their complete observation: %v", repeatErr)
			}
		}
	}
	if len(actualQueries) != 2 || !reflect.DeepEqual(actualQueries[0], actualQueries[1]) {
		t.Fatalf("complete actual Go environment pre/post observations did not close: queries=%d err=%v", len(actualQueries), err)
	}
	for _, actual := range actualQueries {
		if len(actual) != len(discoveryFeatureEnvKeys) {
			t.Fatalf("actual Go environment lost its 13-key inventory: %#v", actual)
		}
		for _, key := range discoveryFeatureEnvKeys {
			if _, present := actual[key]; !present {
				t.Fatalf("actual Go environment omitted %s", key)
			}
		}
	}
	if err != nil {
		t.Fatalf("actual target/cache feature observation failed: %v", err)
	}
	if err := gotoolprofile.Validate(observed); err != nil {
		t.Fatalf("actual target feature observation failed unchanged strict replay: %v", err)
	}
	return observed
}

func featureCPUEnvironmentRoute(env []string) map[string]string {
	result := make(map[string]string)
	for _, item := range env {
		key, value, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		switch key {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GO386", "GOAMD64", "GOARM", "GOARM64", "GOWASM", "GOEXPERIMENT", "GOENV", "GOTOOLCHAIN", "GOWORK", "GOFLAGS", "GOROOT", "GOCACHE":
			result[key] = value
		}
	}
	return result
}

func featureCPUEnvironmentTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	if testDeadline, bounded := t.Deadline(); bounded && testDeadline.Before(deadline) {
		deadline = testDeadline
	}
	return context.WithDeadline(context.Background(), deadline)
}

func logFeatureCPUEnvironment(t *testing.T, label string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s %s", label, data)
}
