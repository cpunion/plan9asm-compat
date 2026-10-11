package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFeatureObservationCacheReusesOnlyCanonicalActualEnvironment(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cache := &discoveryFeatureObservationCache{}
	captures := 0
	cache.capture = func(ctx context.Context, binary, dir string, env []string, target string, overrides map[string]string) (*discoveryTargetFeatures, error) {
		captures++
		return captureDiscoveryTargetFeatures(ctx, binary, dir, env, target, overrides)
	}
	ownedDir := t.TempDir()
	first, err := cache.observe(ctx, goBinary, ownedDir, targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	canonicalID := discoveryFeatureProfileID(first)
	// Neither the caller's map nor an alternate spelling of the same actual
	// defaults may force another marker go-list or rewrite the shared proof.
	first.Environment["GOAMD64"] = "v4"
	second, err := cache.observe(ctx, goBinary, ownedDir, targetFeatureTestEnv(), "linux/amd64", map[string]string{"GOAMD64": "v1"})
	if err != nil || captures != 1 || discoveryFeatureProfileID(second) != canonicalID {
		t.Fatalf("same canonical driver/env was not safely reused: captures=%d id=%s err=%v", captures, discoveryFeatureProfileID(second), err)
	}
	third, err := cache.observe(ctx, goBinary, ownedDir, targetFeatureTestEnv(), "linux/amd64", map[string]string{"GOAMD64": "v3"})
	if err != nil || captures != 2 || third.Environment["GOAMD64"] != "v3" || discoveryFeatureProfileID(third) == canonicalID {
		t.Fatalf("different actual CPU environment reused the baseline observation: captures=%d observed=%+v err=%v", captures, third, err)
	}
}

func TestFeatureObservationCacheRejectsOwnedMarkerMutation(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cache := &discoveryFeatureObservationCache{}
	ownedDir := t.TempDir()
	if _, err := cache.observe(ctx, goBinary, ownedDir, targetFeatureTestEnv(), "linux/amd64", nil); err != nil {
		t.Fatal(err)
	}
	for _, entry := range cache.entries {
		writeTestFile(t, filepath.Join(entry.markerDir, "marker000.go"), "//go:build amd64.v4\n\npackage markers\n")
	}
	if _, err := cache.observe(ctx, goBinary, ownedDir, targetFeatureTestEnv(), "linux/amd64", nil); err == nil {
		t.Fatal("cached marker mutation was accepted as a fresh actual observation")
	}
}

func TestFeatureObservationCacheRejectsEnvironmentOrSourceDrift(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, kind := range []string{"env", "driver", "source", "subtool", "tool-route", "tool-cache"} {
		t.Run(kind, func(t *testing.T) {
			cache := &discoveryFeatureObservationCache{}
			ownedDir := t.TempDir()
			if _, err := cache.observe(ctx, goBinary, ownedDir, targetFeatureTestEnv(), "linux/amd64", nil); err != nil {
				t.Fatal(err)
			}
			checks := 0
			cache.inspect = func(ctx context.Context, binary string, env []string, target string, overrides map[string]string) (*discoveryFeatureDriverState, error) {
				state, err := inspectDiscoveryFeatureDriver(ctx, binary, env, target, overrides)
				checks++
				if checks == 2 && err == nil {
					switch kind {
					case "env":
						state.environment["GOAMD64"] = "v4"
					case "driver":
						state.driverSHA256 = discoveryFeatureBytesSHA256([]byte("different actual driver"))
					case "source":
						state.sourceSHA256["src/internal/buildcfg/cfg.go"] = discoveryFeatureBytesSHA256([]byte("different actual registration"))
					case "subtool":
						state.tools.digests["asm"] = discoveryFeatureBytesSHA256([]byte("different assembler"))
					case "tool-route":
						state.tools.routing = discoveryFeatureBytesSHA256([]byte("different builtin executable route"))
					case "tool-cache":
						state.environment["GOCACHE"] = filepath.Join(t.TempDir(), "different-cache")
					}
				}
				return state, err
			}
			if _, err := cache.observe(ctx, goBinary, ownedDir, targetFeatureTestEnv(), "linux/amd64", nil); err == nil || checks != 2 {
				t.Fatalf("cache hit bypassed before/after actual %s checks: checks=%d err=%v", kind, checks, err)
			}
		})
	}
}

func TestFeatureDriverCacheKeyIncludesRegistrationAndMarkerIdentity(t *testing.T) {
	state := &discoveryFeatureDriverState{environment: map[string]string{"GOAMD64": "v1"}, driverSHA256: "driver", sourceSHA256: map[string]string{"cfg": "source"}, tools: &discoveryFeatureToolState{digests: map[string]string{"asm": "tool"}, routing: "cache"}}
	key := discoveryFeatureDriverStateKey(state)
	clone := *state
	clone.driverSHA256 = "changed"
	if key == discoveryFeatureDriverStateKey(&clone) {
		t.Fatal("driver bytes omitted from cache key")
	}
	clone = *state
	clone.sourceSHA256 = map[string]string{"cfg": "changed"}
	if key == discoveryFeatureDriverStateKey(&clone) {
		t.Fatal("registration bytes omitted from cache key")
	}
	clone = *state
	changedTools := *state.tools
	changedTools.digests = map[string]string{"asm": "changed"}
	clone.tools = &changedTools
	if key == discoveryFeatureDriverStateKey(&clone) {
		t.Fatal("subtool bytes omitted from cache key")
	}
	clone = *state
	clone.environment = map[string]string{"GOAMD64": "v3"}
	if key == discoveryFeatureDriverStateKey(&clone) {
		t.Fatal("actual environment omitted from cache key")
	}
	if !reflect.DeepEqual(state.environment, map[string]string{"GOAMD64": "v1"}) {
		t.Fatal("cache-key calculation mutated actual state")
	}
}

func TestFeatureProfileCaptureSharesOwnedObservationCache(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cache := &discoveryFeatureObservationCache{}
	captures := 0
	cache.capture = func(ctx context.Context, binary, dir string, env []string, target string, overrides map[string]string) (*discoveryTargetFeatures, error) {
		captures++
		return captureDiscoveryTargetFeatures(ctx, binary, dir, env, target, overrides)
	}
	ownedDir := t.TempDir()
	baseline, err := cache.observe(ctx, goBinary, ownedDir, targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := &discoveryOrdinarySelectionPlan{
		Module: "example.invalid/features", GoVersion: baseline.GoVersion,
		Targets: []string{baseline.Target}, Sources: []ordinarySelectionSource{
			{File: "vector_amd64.s", Header: "//go:build amd64.v3\n\n"},
			{File: "vector_amd64.go", Header: "//go:build amd64.v3\n\npackage vector\n"},
		}}
	files := []string{"vector_amd64.s"}
	first, err := captureDiscoveryFeatureProfiles(ctx, goBinary, ownedDir, targetFeatureTestEnv(), plan, files, cache)
	if err != nil {
		t.Fatal(err)
	}
	second, err := captureDiscoveryFeatureProfiles(ctx, goBinary, ownedDir, targetFeatureTestEnv(), plan, files, cache)
	if err != nil || captures != 2 || !reflect.DeepEqual(first, second) {
		t.Fatalf("candidate plans repeated shared marker selection or changed evidence: captures=%d err=%v", captures, err)
	}
}

func TestFeatureObservationCacheConcurrentObserversOwnDeepClones(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cache := &discoveryFeatureObservationCache{}
	var captures int32
	cache.capture = func(ctx context.Context, binary, dir string, env []string, target string, overrides map[string]string) (*discoveryTargetFeatures, error) {
		atomic.AddInt32(&captures, 1)
		return captureDiscoveryTargetFeatures(ctx, binary, dir, env, target, overrides)
	}
	const workers = 4
	type result struct {
		worker   int
		observed *discoveryTargetFeatures
		id       string
		err      error
	}
	root, env := t.TempDir(), targetFeatureTestEnv()
	start, results := make(chan struct{}), make(chan result, workers)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			observed, err := cache.observe(ctx, goBinary, root, env, "linux/amd64", nil)
			if err != nil {
				results <- result{worker: worker, err: err}
				return
			}
			id := discoveryFeatureProfileID(observed)
			// Mutate every nested mutable map while peers observe the shared
			// cache. Returned caller-owned maps must never alias shared proof.
			value := discoveryFeatureBytesSHA256([]byte{byte(worker)})
			observed.Environment["GOAMD64"] = value
			observed.ToolSourceSHA256["VERSION"] = value
			observed.ToolBinarySHA256["asm"] = value
			observed.MarkerSelection["amd64.v1"] = false
			results <- result{worker: worker, observed: observed, id: id}
		}(worker)
	}
	close(start)
	wg.Wait()
	close(results)
	var id string
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if id == "" {
			id = result.id
		}
		value := discoveryFeatureBytesSHA256([]byte{byte(result.worker)})
		if id != result.id || result.observed.Environment["GOAMD64"] != value || result.observed.ToolSourceSHA256["VERSION"] != value || result.observed.ToolBinarySHA256["asm"] != value {
			t.Fatal("concurrent callers shared mutable maps or different actual proofs")
		}
	}
	final, err := cache.observe(ctx, goBinary, root, env, "linux/amd64", nil)
	if err != nil || atomic.LoadInt32(&captures) != 1 || discoveryFeatureProfileID(final) != id || !final.MarkerSelection["amd64.v1"] || final.Environment["GOAMD64"] != "v1" {
		t.Fatalf("concurrent observers damaged shared provenance or repeated markers: captures=%d err=%v", captures, err)
	}
}
