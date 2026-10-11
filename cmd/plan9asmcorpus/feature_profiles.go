package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"math/bits"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type discoveryFeatureProfileRequest struct {
	Target     string            `json:"target"`
	Baseline   bool              `json:"baseline"`
	Overrides  map[string]string `json:"overrides,omitempty"`
	Expected   map[string]bool   `json:"expected_experiments,omitempty"`
	pairs      [][2]string
	customTags []string
}

type discoveryFeatureProfile struct {
	ID       string                         `json:"id"`
	Request  discoveryFeatureProfileRequest `json:"request"`
	Observed *discoveryTargetFeatures       `json:"observed"`
}

// Profiles of different actual targets cannot share a driver observation.
// Bound each target independently; a module-wide count incorrectly excludes
// ordinary multi-platform inputs even when every target stays within its bound.
const discoveryFeatureProfileLimit = 64

type discoveryFeatureProfileBudget map[string]int

func newDiscoveryFeatureProfileBudget(targets []string) (discoveryFeatureProfileBudget, error) {
	if len(targets) == 0 || len(targets) > discoveryFeatureProfileLimit {
		return nil, fmt.Errorf("missing or unbounded feature target matrix")
	}
	budget := make(discoveryFeatureProfileBudget, len(targets))
	for _, target := range targets {
		if err := validateTarget(target); err != nil {
			return nil, err
		}
		if _, duplicate := budget[target]; duplicate {
			return nil, fmt.Errorf("duplicate feature profile target %s", target)
		}
		budget[target] = 0
	}
	return budget, nil
}

func (budget discoveryFeatureProfileBudget) add(target string) error {
	count, present := budget[target]
	if !present {
		return fmt.Errorf("feature profile target %s is outside the complete target matrix", target)
	}
	if count >= discoveryFeatureProfileLimit {
		return fmt.Errorf("source-required target %s feature profiles exceed the explicit %d-profile bound", target, discoveryFeatureProfileLimit)
	}
	budget[target] = count + 1
	return nil
}

// The planning model proposes legal environment settings; it is never an
// execution proof. Every proposal must subsequently be observed by the real
// Go driver, including defaults and experiment dependencies. One matching
// profile per source pair preserves feature-only inputs without claiming an
// exhaustive enumeration of all possible toolchain experiment combinations.
func planDiscoveryFeatureProfiles(plan *discoveryOrdinarySelectionPlan, asmFiles []string, baselines []*discoveryTargetFeatures, contexts ...context.Context) ([]discoveryFeatureProfileRequest, error) {
	if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
		return nil, err
	}
	if plan == nil || len(plan.Targets) != len(baselines) {
		return nil, fmt.Errorf("incomplete feature profile baselines")
	}
	budget, err := newDiscoveryFeatureProfileBudget(plan.Targets)
	if err != nil {
		return nil, err
	}
	plan.headerPlanningUsed = make(map[string]bool)
	if err := ordinarySelectionPackagePathError(plan.Module, "."); err != nil {
		return nil, fmt.Errorf("feature profiles require a valid module import path: %w", err)
	}
	if plan.InstrumentationPlan != nil {
		if err := validateDiscoveryInstrumentationDenominator(plan, asmFiles, baselines); err != nil {
			return nil, err
		}
	}
	var requests []discoveryFeatureProfileRequest
	byKey := make(map[string]int)
	contents := make(map[string][]byte)
	for _, source := range plan.Sources {
		if _, duplicate := contents[source.File]; duplicate {
			return nil, fmt.Errorf("duplicate profile source %s", source.File)
		}
		contents[source.File] = []byte(source.Header)
	}
	add := func(request discoveryFeatureProfileRequest) error {
		key := discoveryFeatureRequestKey(request)
		if index, ok := byKey[key]; ok {
			previous := &requests[index]
			if previous.Expected == nil && len(request.Expected) > 0 {
				previous.Expected = make(map[string]bool)
			}
			for tag, expected := range request.Expected {
				if old, exists := previous.Expected[tag]; exists && old != expected {
					return fmt.Errorf("conflicting experiment profile proposals for %s", tag)
				}
				previous.Expected[tag] = expected
			}
			previous.pairs = append(previous.pairs, request.pairs...)
			return nil
		}
		if err := budget.add(request.Target); err != nil {
			return err
		}
		byKey[key] = len(requests)
		requests = append(requests, request)
		return nil
	}
	seenTargets := make(map[string]bool)
	cppSources := &discoveryCPPPlanningSourceIndex{}
	for _, baseline := range baselines {
		if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
			return nil, err
		}
		if baseline == nil || baseline.GoVersion != plan.GoVersion || seenTargets[baseline.Target] || !containsTargetFeature(plan.Targets, baseline.Target) {
			return nil, fmt.Errorf("missing or conflicting actual feature baseline")
		}
		seenTargets[baseline.Target] = true
		if err := add(discoveryFeatureProfileRequest{Target: baseline.Target, Baseline: true}); err != nil {
			return nil, err
		}
		ctx, err := discoveryContextForFeatureProfile(baseline)
		if err != nil {
			return nil, err
		}
		ctx.OpenFile = func(file string) (io.ReadCloser, error) {
			if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
				return nil, err
			}
			data, exists := contents[filepath.ToSlash(file)]
			if !exists {
				return nil, fmt.Errorf("uncaptured profile source %s", file)
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		for _, asmFile := range asmFiles {
			if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
				return nil, err
			}
			if _, exists := contents[asmFile]; !exists {
				return nil, fmt.Errorf("missing profile assembly source %s", asmFile)
			}
			if discoveryDirIsIgnored(path.Dir(asmFile)) || discoveryFeatureNestedSource(plan, path.Dir(asmFile)) ||
				ordinarySelectionPackagePathError(plan.Module, path.Dir(asmFile)) != nil {
				continue
			}
			var goFiles []string
			for name, data := range contents {
				if path.Dir(name) != path.Dir(asmFile) || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(path.Base(name), "_") || strings.HasPrefix(path.Base(name), ".") {
					continue
				}
				if _, err := parser.ParseFile(token.NewFileSet(), name, data, parser.PackageClauseOnly); err == nil {
					goFiles = append(goFiles, name)
				}
			}
			sort.Strings(goFiles)
			for _, goFile := range goFiles {
				if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
					return nil, err
				}
				var selection *discoveryInstrumentationSelectionModel
				if discoveryInstrumentationAssemblyRequired(plan, asmFile, baseline.Target) {
					selection = &discoveryInstrumentationSelectionModel{}
				}
				request, found, err := planDiscoveryFeaturePairWithMode(ctx, baseline, asmFile, goFile, selection)
				if err != nil {
					return nil, fmt.Errorf("profile for %s + %s on %s: %w", asmFile, goFile, baseline.Target, err)
				}
				if found {
					request.pairs = [][2]string{{asmFile, goFile}}
					if err := add(request); err != nil {
						return nil, err
					}
					cppRequests, err := planDiscoveryCPPFeaturePairWithIndex(plan, ctx, baseline, asmFile, goFile,
						request, nil, cppSources, contexts...)
					if err != nil {
						return nil, fmt.Errorf("CPP profiles for %s + %s on %s: %w", asmFile, goFile, baseline.Target, err)
					}
					for _, cppRequest := range cppRequests {
						if err := add(cppRequest); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	sort.Slice(requests, func(i, j int) bool {
		return discoveryFeatureRequestKey(requests[i]) < discoveryFeatureRequestKey(requests[j])
	})
	if err := validateDiscoveryPlanningConsumption(plan); err != nil {
		return nil, err
	}
	return requests, nil
}

func discoveryFeatureNestedSource(plan *discoveryOrdinarySelectionPlan, dir string) bool {
	for ancestor := dir; ancestor != "."; ancestor = path.Dir(ancestor) {
		for _, directory := range plan.Directories {
			if directory.Directory != ancestor {
				continue
			}
			for _, entry := range directory.Entries {
				if entry.Name == "go.mod" && entry.Kind == "file" {
					return true
				}
			}
		}
	}
	return false
}

func discoveryContextForFeatureProfile(features *discoveryTargetFeatures) (build.Context, error) {
	ctx := build.Default
	parts := strings.Split(features.Target, "/")
	minor, err := discoveryGoMinor(features.GoVersion)
	if len(parts) != 2 || err != nil {
		return ctx, fmt.Errorf("invalid actual profile target or Go version")
	}
	ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = parts[0], parts[1], "gc", false
	ctx.BuildTags, ctx.ReleaseTags = nil, nil
	for release := 1; release <= minor; release++ {
		ctx.ReleaseTags = append(ctx.ReleaseTags, fmt.Sprintf("go1.%d", release))
	}
	ctx.ToolTags = append([]string(nil), features.ToolTags...)
	return ctx, nil
}

func planDiscoveryFeaturePair(ctx build.Context, baseline *discoveryTargetFeatures, asmFile, goFile string) (discoveryFeatureProfileRequest, bool, error) {
	return planDiscoveryFeaturePairWithMode(ctx, baseline, asmFile, goFile, nil)
}

// A non-nil selection is a source-predicate model only. The corpus mode
// protocol independently binds its actual exclusive driver flags later.
func planDiscoveryFeaturePairWithMode(ctx build.Context, baseline *discoveryTargetFeatures, asmFile, goFile string, selection *discoveryInstrumentationSelectionModel) (discoveryFeatureProfileRequest, bool, error) {
	return planDiscoveryFeaturePairWithExpressions(ctx, baseline, asmFile, goFile, selection, func(file string) (constraint.Expr, error) {
		return discoveryFileBuildExpression(file, ctx.OpenFile)
	})
}

// Ordinary callers retain their original parser. Only instrumentation's
// per-call source index supplies a memoized expression reader; stock filename
// and final MatchFile selection still read the exact original source.
func planDiscoveryFeaturePairWithExpressions(ctx build.Context, baseline *discoveryTargetFeatures, asmFile, goFile string, selection *discoveryInstrumentationSelectionModel, expression func(string) (constraint.Expr, error)) (discoveryFeatureProfileRequest, bool, error) {
	if selection != nil {
		ctx.CgoEnabled = selection.CGO
		if selection.Mode != "" {
			ctx.ToolTags = append(append([]string(nil), ctx.ToolTags...), string(selection.Mode))
		}
	}
	filenameContext := ctx
	filenameContext.OpenFile = func(string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil }
	for _, file := range []string{asmFile, goFile} {
		matches, err := filenameContext.MatchFile(filepath.FromSlash(path.Dir(file)), path.Base(file))
		if err != nil || !matches {
			return discoveryFeatureProfileRequest{}, false, err
		}
	}
	tagsByFile := make(map[string][]string)
	var allTags []string
	var expressions []constraint.Expr
	for _, file := range []string{asmFile, goFile} {
		expr, err := expression(filepath.FromSlash(file))
		if err != nil {
			return discoveryFeatureProfileRequest{}, false, err
		}
		set := make(map[string]bool)
		if expr != nil {
			collectDiscoveryConstraintTags(expr, set)
		}
		expressions = append(expressions, expr)
		tagsByFile[filepath.FromSlash(file)] = sortedDiscoverySet(set)
		allTags = append(allTags, tagsByFile[filepath.FromSlash(file)]...)
	}
	custom := discoveryCustomTagsWithoutFeatures(allTags, []build.Context{ctx})
	// Prune fixed-false targets, release guards and ignored generators before
	// considering feature profiles. They are not latent feature-only input.
	fixed := map[string]bool{"ignore": false, "cgo": false, "gc": true, "gccgo": false}
	if selection != nil {
		fixed["cgo"] = selection.CGO
		for _, mode := range []string{"race", "msan", "asan"} {
			fixed[mode] = mode == string(selection.Mode)
		}
	}
	for _, tag := range uniqueSortedDiscoveryStrings(allTags) {
		if containsTargetFeature(custom, tag) || tag == "boringcrypto" || strings.HasPrefix(tag, "goexperiment.") || strings.HasPrefix(tag, ctx.GOARCH+".") || tag == "race" || tag == "msan" || tag == "asan" {
			continue
		}
		oneTag := ctx
		oneTag.OpenFile = func(string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("//go:build " + tag + "\n\npackage markers\n")), nil
		}
		value, err := oneTag.MatchFile(".", "marker.go")
		if err != nil {
			return discoveryFeatureProfileRequest{}, false, err
		}
		fixed[tag] = value
	}
	for _, expr := range expressions {
		if !discoveryExpressionMayMatch(expr, fixed) {
			return discoveryFeatureProfileRequest{}, false, nil
		}
	}
	if selection == nil && ordinaryInstrumentationGoPartnerMayMatch(expressions[0]) && !ordinaryInstrumentationGoPartnerMayMatch(expressions[1]) {
		return discoveryFeatureProfileRequest{}, false, nil
	}
	var experimentVars []string
	var unsupported []string
	cpuMentioned := false
	for _, tag := range uniqueSortedDiscoveryStrings(allTags) {
		if tag == "boringcrypto" {
			tag = "goexperiment.boringcrypto"
		}
		if strings.HasPrefix(tag, "goexperiment.") {
			if _, known := baseline.MarkerSelection[tag]; !known {
				unsupported = append(unsupported, tag)
				continue
			}
			experimentVars = append(experimentVars, tag)
		} else if strings.HasPrefix(tag, ctx.GOARCH+".") {
			if _, known := baseline.MarkerSelection[tag]; !known {
				unsupported = append(unsupported, tag)
				continue
			}
			cpuMentioned = true
		} else if tag == "race" || tag == "msan" || tag == "asan" {
			if selection == nil {
				unsupported = append(unsupported, tag)
			}
		}
	}
	experimentVars = uniqueSortedDiscoveryStrings(experimentVars)
	if len(experimentVars) > 8 {
		return discoveryFeatureProfileRequest{}, false, fmt.Errorf("source pair exceeds explicit 8-experiment planning bound")
	}
	cpuKey := map[string]string{"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM"}[ctx.GOARCH]
	cpuValues := []string{baseline.Environment[cpuKey]}
	if cpuMentioned {
		if ctx.GOARCH == "wasm" {
			cpuValues = append(cpuValues, "", "satconv", "signext", "satconv,signext")
		}
		for _, tag := range discoveryCPUFeatureCandidates() {
			if strings.HasPrefix(tag, ctx.GOARCH+".") {
				cpuValues = append(cpuValues, strings.TrimPrefix(tag, ctx.GOARCH+"."))
			}
		}
	}
	cpuValues = uniqueDiscoveryStrings(cpuValues)
	minor, _ := discoveryGoMinor(baseline.GoVersion)
	for _, cpuValue := range cpuValues {
		if err := validateDiscoveryCPUEnvironment(ctx.GOARCH, cpuValue, minor); err != nil {
			continue
		}
		for changes := 0; changes <= len(experimentVars); changes++ {
			for mask := 0; mask < 1<<len(experimentVars); mask++ {
				if bits.OnesCount(uint(mask)) != changes {
					continue
				}
				model := ctx
				model.ToolTags = discoveryModeledCPUFeatures(ctx.ToolTags, ctx.GOARCH, cpuValue, minor)
				var expected map[string]bool
				if len(experimentVars) > 0 {
					expected = make(map[string]bool)
				}
				var toggles []string
				for index, tag := range experimentVars {
					value := baseline.MarkerSelection[tag]
					if mask&(1<<index) != 0 {
						value = !value
						name := strings.TrimPrefix(tag, "goexperiment.")
						if !value {
							name = "no" + name
						}
						toggles = append(toggles, name)
					}
					expected[tag] = value
					var kept []string
					for _, old := range model.ToolTags {
						if old != tag {
							kept = append(kept, old)
						}
					}
					if value {
						kept = append(kept, tag)
					}
					model.ToolTags = kept
				}
				tags, matches, err := findDiscoveryBuildTags(model, filepath.FromSlash(path.Dir(asmFile)), path.Base(asmFile), []string{path.Base(goFile)}, custom, tagsByFile)
				if err != nil {
					return discoveryFeatureProfileRequest{}, false, err
				}
				if !matches {
					continue
				}
				request := discoveryFeatureProfileRequest{Target: baseline.Target, Overrides: make(map[string]string), Expected: expected}
				request.customTags = append([]string(nil), tags...)
				if cpuValue != baseline.Environment[cpuKey] {
					request.Overrides[cpuKey] = cpuValue
				}
				if len(toggles) != 0 {
					parts := append([]string{baseline.Environment["GOEXPERIMENT"]}, toggles...)
					request.Overrides["GOEXPERIMENT"] = strings.TrimPrefix(strings.Join(parts, ","), ",")
				}
				request.Baseline = len(request.Overrides) == 0
				return request, true, nil
			}
		}
	}
	if len(unsupported) != 0 {
		return discoveryFeatureProfileRequest{}, false, fmt.Errorf("source requires an unsupported feature profile; not baseline N/A: %s", strings.Join(unsupported, ", "))
	}
	return discoveryFeatureProfileRequest{}, false, nil
}

func discoveryModeledCPUFeatures(tags []string, arch, value string, minor int) []string {
	return gotoolprofile.CPUFeatures(tags, arch, value, minor)
}

func discoveryFeatureRequestKey(request discoveryFeatureProfileRequest) string {
	overrides := request.Overrides
	if len(overrides) == 0 {
		overrides = nil
	}
	data, _ := json.Marshal(struct {
		Target    string
		Overrides map[string]string
	}{request.Target, overrides})
	return string(data)
}

func captureDiscoveryFeatureProfiles(ctx context.Context, goBinary, ownedDir string, env []string, plan *discoveryOrdinarySelectionPlan, asmFiles []string, caches ...*discoveryFeatureObservationCache) ([]discoveryFeatureProfile, error) {
	if len(caches) > 1 || len(caches) == 1 && caches[0] == nil {
		return nil, fmt.Errorf("feature profiles require one owned actual-observation cache")
	}
	observe := func(name, target string, overrides map[string]string) (*discoveryTargetFeatures, error) {
		if len(caches) == 1 {
			return caches[0].observe(ctx, goBinary, ownedDir, env, target, overrides)
		}
		dir := filepath.Join(ownedDir, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
		return captureDiscoveryTargetFeatures(ctx, goBinary, dir, env, target, overrides)
	}
	var baselines []*discoveryTargetFeatures
	for index, target := range plan.Targets {
		observed, err := observe(fmt.Sprintf("baseline-%03d", index), target, nil)
		if err != nil {
			return nil, err
		}
		baselines = append(baselines, observed)
	}
	if err := captureDiscoveryInstrumentationDenominator(plan, asmFiles, baselines); err != nil {
		return nil, err
	}
	requests, err := planDiscoveryFeatureProfiles(plan, asmFiles, baselines, ctx)
	if err != nil {
		return nil, err
	}
	var profiles []discoveryFeatureProfile
	for index, request := range requests {
		var observed *discoveryTargetFeatures
		if request.Baseline {
			for _, baseline := range baselines {
				if baseline.Target == request.Target {
					observed = baseline
				}
			}
		} else {
			observed, err = observe(fmt.Sprintf("profile-%03d", index), request.Target, request.Overrides)
			if err != nil {
				return nil, fmt.Errorf("actual driver rejected required profile %s: %w", discoveryFeatureRequestKey(request), err)
			}
		}
		for tag, expected := range request.Expected {
			if actual, recorded := observed.MarkerSelection[tag]; !recorded || actual != expected {
				return nil, fmt.Errorf("actual driver contradicted required experiment %s=%t on %s", tag, expected, request.Target)
			}
		}
		profile := discoveryFeatureProfile{ID: discoveryFeatureProfileID(observed), Request: request, Observed: observed}
		profiles = append(profiles, profile)
	}
	if err := validateDiscoveryFeatureProfiles(plan, asmFiles, profiles, ctx); err != nil {
		return nil, fmt.Errorf("actual source-required profiles: %w", err)
	}
	return profiles, nil
}

func validateDiscoveryFeatureProfiles(plan *discoveryOrdinarySelectionPlan, asmFiles []string, profiles []discoveryFeatureProfile, contexts ...context.Context) error {
	if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
		return err
	}
	if plan == nil || len(profiles) == 0 || len(plan.Targets) == 0 {
		return fmt.Errorf("missing or unbounded source-required actual feature profiles")
	}
	budget, err := newDiscoveryFeatureProfileBudget(plan.Targets)
	if err != nil {
		return err
	}
	if len(profiles) > len(budget)*discoveryFeatureProfileLimit {
		return fmt.Errorf("actual feature profiles exceed the complete target matrix bound")
	}
	var baselines []*discoveryTargetFeatures
	byRequest, byID := make(map[string]discoveryFeatureProfile), make(map[string]bool)
	for _, profile := range profiles {
		if err := checkDiscoveryProfilePlanningContext(contexts); err != nil {
			return err
		}
		if err := budget.add(profile.Request.Target); err != nil {
			return err
		}
		if err := validateDiscoveryTargetFeatures(profile.Observed); err != nil {
			return err
		}
		if profile.ID != discoveryFeatureProfileID(profile.Observed) || byID[profile.ID] || profile.Request.Target != profile.Observed.Target || profile.Observed.GoVersion != plan.GoVersion {
			return fmt.Errorf("invalid, duplicate or cross-version actual feature profile identity")
		}
		byID[profile.ID] = true
		key := discoveryFeatureRequestKey(profile.Request)
		if _, duplicate := byRequest[key]; duplicate || profile.Request.Baseline != (len(profile.Request.Overrides) == 0) {
			return fmt.Errorf("duplicate or inconsistent feature profile request")
		}
		byRequest[key] = profile
		cpuKey := map[string]string{"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM"}[profile.Observed.Environment["GOARCH"]]
		for key, value := range profile.Request.Overrides {
			if key != cpuKey && key != "GOEXPERIMENT" || profile.Observed.Environment[key] != value {
				return fmt.Errorf("unobserved or arbitrary custom feature override %s", key)
			}
		}
		for tag, expected := range profile.Request.Expected {
			if actual, present := profile.Observed.MarkerSelection[tag]; !present || actual != expected {
				return fmt.Errorf("actual driver contradicted source-required experiment %s", tag)
			}
		}
		if profile.Request.Baseline {
			baselines = append(baselines, profile.Observed)
		}
	}
	wanted, err := planDiscoveryFeatureProfiles(plan, asmFiles, baselines, contexts...)
	if err != nil {
		return err
	}
	if len(wanted) != len(profiles) {
		return fmt.Errorf("feature-only source scope missing or unexplained profile added")
	}
	identity := profiles[0].Observed
	for _, request := range wanted {
		profile, present := byRequest[discoveryFeatureRequestKey(request)]
		if !present || !reflect.DeepEqual(profile.Request.Expected, request.Expected) || profile.Request.Baseline != request.Baseline {
			return fmt.Errorf("actual profile requests do not cover exact source-required proposals")
		}
		observed := profile.Observed
		if observed.DriverSHA256 != identity.DriverSHA256 ||
			!reflect.DeepEqual(observed.ToolSourceSHA256, identity.ToolSourceSHA256) ||
			observed.ToolDirectory != identity.ToolDirectory ||
			observed.ToolDispatcherSHA256 != identity.ToolDispatcherSHA256 ||
			observed.MarkerSourceSHA256 != identity.MarkerSourceSHA256 {
			return fmt.Errorf("feature profiles used different actual driver/registration/marker inputs")
		}
		for _, tool := range discoveryFeatureSubtools {
			origin := observed.ToolBinaryOrigins[tool]
			if origin != identity.ToolBinaryOrigins[tool] || strings.HasPrefix(origin, "goroot/") && observed.ToolBinarySHA256[tool] != identity.ToolBinarySHA256[tool] {
				return fmt.Errorf("feature profiles used different installed Go %s tools", tool)
			}
		}
		for _, pair := range request.pairs {
			if err := validateDiscoveryFeatureSourcePair(plan, observed, pair); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateDiscoveryFeatureSourcePair(plan *discoveryOrdinarySelectionPlan, observed *discoveryTargetFeatures, pair [2]string) error {
	ctx, err := discoveryContextForFeatureProfile(observed)
	if err != nil {
		return err
	}
	contents := make(map[string]string)
	for _, input := range plan.Sources {
		contents[input.File] = input.Header
	}
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		data, present := contents[filepath.ToSlash(file)]
		if !present {
			return nil, fmt.Errorf("actual profile lacks source header %s", file)
		}
		return io.NopCloser(strings.NewReader(data)), nil
	}
	tagsByFile := make(map[string][]string)
	var allTags []string
	for _, file := range pair {
		expression, err := discoveryFileBuildExpression(filepath.FromSlash(file), ctx.OpenFile)
		if err != nil {
			return err
		}
		set := make(map[string]bool)
		if expression != nil {
			collectDiscoveryConstraintTags(expression, set)
		}
		tagsByFile[filepath.FromSlash(file)] = sortedDiscoverySet(set)
		allTags = append(allTags, tagsByFile[filepath.FromSlash(file)]...)
	}
	custom := discoveryCustomTagsWithoutFeatures(allTags, []build.Context{ctx})
	_, selected, err := findDiscoveryBuildTags(ctx, filepath.FromSlash(path.Dir(pair[0])), path.Base(pair[0]), []string{path.Base(pair[1])}, custom, tagsByFile)
	if err != nil || !selected {
		return fmt.Errorf("actual profile does not select required assembly/Go source pair %s + %s: %v", pair[0], pair[1], err)
	}
	return nil
}
