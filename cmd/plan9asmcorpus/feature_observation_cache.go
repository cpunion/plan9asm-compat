package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type discoveryFeatureDriverState struct {
	environment  map[string]string
	driverSHA256 string
	sourceSHA256 map[string]string
	tools        *discoveryFeatureToolState
}

type discoveryCachedFeatureObservation struct {
	markerDir string
	observed  *discoveryTargetFeatures
}

type discoveryFeatureObservationCache struct {
	mu      sync.Mutex
	root    string
	entries map[string]discoveryCachedFeatureObservation
	capture func(context.Context, string, string, []string, string, map[string]string) (*discoveryTargetFeatures, error)
	inspect func(context.Context, string, []string, string, map[string]string) (*discoveryFeatureDriverState, error)
}

func (cache *discoveryFeatureObservationCache) observe(ctx context.Context, binary, root string, env []string, target string, overrides map[string]string) (*discoveryTargetFeatures, error) {
	// Cache only immutable observations. Every use still performs real go-env
	// and driver/registration byte checks on both sides; only marker go-list
	// is reused. The caller owns this directory and its complete lifetime.
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("feature observation cache requires an owned absolute directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if cache.root != "" && cache.root != resolvedRoot {
		return nil, fmt.Errorf("feature observation cache ownership directory changed")
	}
	cache.root = resolvedRoot
	inspect := cache.inspect
	if inspect == nil {
		inspect = inspectDiscoveryFeatureDriver
	}
	before, err := inspect(ctx, binary, env, target, overrides)
	if err != nil {
		return nil, err
	}
	key := discoveryFeatureDriverStateKey(before)
	entry, present := cache.entries[key]
	if !present {
		dir, err := os.MkdirTemp(resolvedRoot, "feature-markers-")
		if err != nil {
			return nil, err
		}
		capture := cache.capture
		if capture == nil {
			capture = captureDiscoveryTargetFeatures
		}
		observed, err := capture(ctx, binary, dir, env, target, overrides)
		if err != nil {
			return nil, err
		}
		entry = discoveryCachedFeatureObservation{markerDir: dir, observed: observed}
	}
	if err := validateDiscoveryCachedFeatures(entry, before); err != nil {
		return nil, err
	}
	after, err := inspect(ctx, binary, env, target, overrides)
	if err != nil {
		return nil, err
	}
	if discoveryFeatureDriverStateKey(after) != key {
		return nil, fmt.Errorf("actual feature environment/driver/registration changed during cache use")
	}
	if err := validateDiscoveryCachedFeatures(entry, after); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(entry.observed)
	if err != nil {
		return nil, err
	}
	var owned, result discoveryTargetFeatures
	if err := json.Unmarshal(canonical, &owned); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(canonical, &result); err != nil {
		return nil, err
	}
	if cache.entries == nil {
		cache.entries = make(map[string]discoveryCachedFeatureObservation)
	}
	entry.observed = &owned
	cache.entries[key] = entry
	return &result, nil
}

func inspectDiscoveryFeatureDriver(ctx context.Context, binary string, env []string, target string, overrides map[string]string) (*discoveryFeatureDriverState, error) {
	parts := strings.Split(target, "/")
	if !filepath.IsAbs(binary) || len(parts) != 2 || parts[0] == "" {
		return nil, fmt.Errorf("invalid actual feature driver/target")
	}
	cpuKey := map[string]string{"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM"}[parts[1]]
	if cpuKey == "" {
		return nil, fmt.Errorf("unsupported actual feature target %s", target)
	}
	env, err := gotoolprofile.FeatureCommandEnvironment(env, target, overrides)
	if err != nil {
		return nil, err
	}
	driverHash, err := discoveryFeatureFileSHA256(binary)
	if err != nil {
		return nil, err
	}
	args := append([]string{"env", "-json"}, discoveryFeatureEnvKeys...)
	output, _, err := runDiscoveryMachineCommand(ctx, "", env, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("inspect actual feature environment: %w", err)
	}
	var actual map[string]string
	if err := json.Unmarshal(output, &actual); err != nil || len(actual) != len(discoveryFeatureEnvKeys) {
		return nil, fmt.Errorf("inspect incomplete actual feature environment: %v", err)
	}
	for _, key := range discoveryFeatureEnvKeys {
		if _, present := actual[key]; !present {
			return nil, fmt.Errorf("inspect missing actual feature environment %s", key)
		}
	}
	if actual["GOOS"] != parts[0] || actual["GOARCH"] != parts[1] || actual["CGO_ENABLED"] != "0" || !filepath.IsAbs(actual["GOROOT"]) {
		return nil, fmt.Errorf("actual feature inspection returned a different target/root")
	}
	for key, wanted := range overrides {
		if actual[key] != wanted {
			return nil, fmt.Errorf("actual feature inspection did not preserve %s", key)
		}
	}
	minor, err := discoveryGoMinor(actual["GOVERSION"])
	if err != nil || minor < 20 || minor > 27 {
		return nil, fmt.Errorf("unaudited actual feature version %s", actual["GOVERSION"])
	}
	if err := validateDiscoveryCPUEnvironment(parts[1], actual[cpuKey], minor); err != nil {
		return nil, err
	}
	sources := make(map[string]string)
	for _, file := range []string{"VERSION", "src/internal/buildcfg/cfg.go", "src/internal/goexperiment/flags.go"} {
		digest, err := discoveryFeatureFileSHA256(filepath.Join(actual["GOROOT"], filepath.FromSlash(file)))
		if err != nil {
			return nil, err
		}
		sources[file] = digest
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, binary, env, actual)
	if err != nil {
		return nil, err
	}
	return &discoveryFeatureDriverState{environment: actual, driverSHA256: driverHash, sourceSHA256: sources, tools: tools}, nil
}

func discoveryFeatureDriverStateKey(state *discoveryFeatureDriverState) string {
	data, _ := json.Marshal(struct {
		Protocol         string
		MarkerModule     string
		Environment      map[string]string
		DriverSHA256     string
		SourceSHA256     map[string]string
		ToolDirectory    string
		ToolSHA256       map[string]string
		ToolOrigins      map[string]string
		ToolRouting      string
		DispatcherSHA256 string
	}{
		Protocol: "go_driver_feature_cache_v2", MarkerModule: discoveryFeatureMarkerModule,
		Environment: state.environment, DriverSHA256: state.driverSHA256,
		SourceSHA256: state.sourceSHA256, ToolDirectory: state.tools.directory,
		ToolSHA256: state.tools.digests, ToolOrigins: state.tools.origins,
		ToolRouting: state.tools.routing, DispatcherSHA256: state.tools.dispatcher,
	})
	return discoveryFeatureBytesSHA256(data)
}

func validateDiscoveryCachedFeatures(entry discoveryCachedFeatureObservation, state *discoveryFeatureDriverState) error {
	if err := validateDiscoveryTargetFeatures(entry.observed); err != nil {
		return err
	}
	actualEnv := make(map[string]string)
	for key, value := range state.environment {
		if key != "GOROOT" && key != "GOTOOLDIR" && key != "GOCACHE" {
			actualEnv[key] = value
		}
	}
	recordedTools := &discoveryFeatureToolState{
		directory: entry.observed.ToolDirectory, digests: entry.observed.ToolBinarySHA256,
		origins: entry.observed.ToolBinaryOrigins, routing: entry.observed.ToolRoutingSHA256,
		dispatcher: entry.observed.ToolDispatcherSHA256,
	}
	if !reflect.DeepEqual(actualEnv, entry.observed.Environment) ||
		entry.observed.DriverSHA256 != state.driverSHA256 ||
		!reflect.DeepEqual(entry.observed.ToolSourceSHA256, state.sourceSHA256) ||
		!equalDiscoveryFeatureToolStates(recordedTools, state.tools) {
		return fmt.Errorf("cached feature proof differs from actual driver/environment/registration")
	}
	var tags []string
	for tag := range entry.observed.MarkerSelection {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	files := discoveryFeatureMarkerFiles(tags)
	if discoveryFeatureMarkerSHA256(files) != entry.observed.MarkerSourceSHA256 {
		return fmt.Errorf("cached feature marker identity differs from audited namespace")
	}
	entries, err := os.ReadDir(entry.markerDir)
	if err != nil || len(entries) != len(files) {
		return fmt.Errorf("cached owned feature marker inventory changed")
	}
	for name, wanted := range files {
		actual, err := os.ReadFile(filepath.Join(entry.markerDir, name))
		if err != nil || !bytes.Equal(actual, wanted) {
			return fmt.Errorf("cached owned feature marker bytes changed: %s", name)
		}
	}
	return nil
}
