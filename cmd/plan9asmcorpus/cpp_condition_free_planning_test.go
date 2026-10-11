package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/build"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// These are query-only models. The captured feature fixture supplies the
// audited namespace, but the callbacks below do not run a compiler or create
// MetadataProof, source, generated-header, LLVM, or library pass authority.
// Counting distinct requests mirrors the existing producer's exact-key cache.
type conditionFreePlanningFixture struct {
	plan     *discoveryOrdinarySelectionPlan
	baseline *discoveryTargetFeatures
	context  build.Context
	assembly string
	queries  map[string]int
	selected map[string][]string
	adjust   func(*gotoolprofile.GeneratedHeaderProof)
}

var conditionFreePlanningTargets = []string{
	"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm",
}

func newConditionFreePlanningFixture(t *testing.T, target, body string, extra map[string]string) *conditionFreePlanningFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/go127_feature_protocol_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var captured featureProtocolFixture
	if err := json.Unmarshal(data, &captured); err != nil {
		t.Fatal(err)
	}
	baseline := captured.Observed[target]
	if baseline == nil {
		t.Fatalf("missing captured namespace fixture for %s", target)
	}
	context, err := discoveryContextForFeatureProfile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	assembly := "pkg/probe_" + context.GOARCH + ".s"
	sources := map[string]string{
		"go.mod": "module example.invalid/condition-free\n\ngo 1.20\n",
		"pkg/decl.go": "package fixture\n" +
			"type Record struct { Value uint64 }\n" +
			"const Truth = true\nconst Text = \"#ifdef GOAMD64_v3\"\nfunc Probe()\n",
		assembly: "#include \"go_asm.h\"\n" + body +
			"TEXT ·Probe(SB),4,$0-0\nRET\nGLOBL ·recordMarker(SB),$Record__size\n",
	}
	for file, text := range extra {
		sources[file] = text
	}
	plan := &discoveryOrdinarySelectionPlan{
		Module: "example.invalid/condition-free", Version: "v1.0.0",
		GoVersion: baseline.GoVersion, Targets: []string{target},
		// Syntactic model identities, not evidence of a physical ZIP.
		ModuleSum: "h1:" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		ZipSHA256: discoveryFeatureBytesSHA256([]byte("query-only graph fixture")),
	}
	var names []string
	for file := range sources {
		names = append(names, file)
	}
	sort.Strings(names)
	for _, file := range names {
		text := sources[file]
		plan.Sources = append(plan.Sources, ordinarySelectionSource{
			File: file, Header: text, SHA256: discoveryFeatureBytesSHA256([]byte(text)),
		})
	}
	input := &discoveryCPPInputs{
		Protocol: discoveryReplayCPPInputsProtocol, Module: plan.Module, Version: plan.Version,
		ModuleSum: plan.ModuleSum, ZipSHA256: plan.ZipSHA256,
		Registration: captured.CPP, Sources: make(map[string]discoveryCPPSource),
	}
	for _, file := range names {
		if !strings.HasSuffix(file, ".s") && !strings.HasSuffix(file, ".h") {
			continue
		}
		parsed, err := discoveryReplayCPPSource(file, []byte(sources[file]))
		if err != nil {
			t.Fatal(err)
		}
		input.Sources["module/"+file] = parsed
	}
	unit := discoveryCPPUnit{
		File: assembly, Includes: make(map[string]string), DeferredIncludes: make(map[string]string),
	}
	for id, source := range input.Sources {
		resources, err := discoveryCPPRegisteredResources(input, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, resource := range resources {
			key := id + resource.key
			module, _, err := gotoolprofile.CPPIncludeCandidates(assembly, resource.directive.Include)
			if resource.directive.Include == "go_asm.h" {
				unit.DeferredIncludes[key] = "generated_go_asm"
			} else if err == nil && input.Sources["module/"+module].Original != nil {
				unit.Includes[key] = "module/" + module
			} else if resource.candidate {
				unit.DeferredIncludes[key] = "unresolved_candidate"
			} else {
				unit.DeferredIncludes[key] = "unresolved_include"
			}
		}
	}
	input.Units = []discoveryCPPUnit{unit}
	plan.CPPInputs = input
	if err := validateDiscoveryReplayCPPInputs(input, plan, []string{assembly}); err != nil {
		t.Fatalf("query-model graph preparation: %v", err)
	}
	context.OpenFile = func(file string) (io.ReadCloser, error) {
		text, found := sources[file]
		if !found {
			return nil, fmt.Errorf("uncaptured query-model source %s", file)
		}
		return io.NopCloser(strings.NewReader(text)), nil
	}
	return &conditionFreePlanningFixture{
		plan: plan, baseline: baseline, context: context, assembly: assembly,
		queries: make(map[string]int), selected: make(map[string][]string),
	}
}

func (fixture *conditionFreePlanningFixture) header(t *testing.T, request discoveryFeatureProfileRequest, assembly string) (*gotoolprofile.GeneratedHeaderProof, error) {
	t.Helper()
	if assembly != fixture.assembly || request.Target != fixture.baseline.Target {
		t.Fatalf("query escaped its target/source model: %s %+v", assembly, request)
	}
	key := discoveryHeaderPlanningKey(request, assembly, request.customTags)
	if fixture.queries[key] == 0 {
		fixture.queries[key] = len(fixture.queries) + 1
	}
	// Independent source replay supplies the full canonical grammar, including
	// boolean and quoted string constants. It is not a native object witness.
	sources, err := fixture.selectedGoSources(request)
	if err != nil {
		return nil, err
	}
	var names []string
	for file := range sources {
		names = append(names, file)
	}
	sort.Strings(names)
	fixture.selected[key] = names
	definitions, err := gotoolprofile.ReplayNativeGeneratedHeader(
		fixture.plan.Module+"/pkg", request.Target, "go1.20", sources,
	)
	if err != nil {
		return nil, err
	}
	if definitions["const_Truth"] != "true" || definitions["const_Text"] != "\"#ifdef GOAMD64_v3\"" ||
		definitions["Record__size"] != "8" {
		return nil, fmt.Errorf("query-model canonical boolean/string/layout preparation is incomplete")
	}
	header := &gotoolprofile.GeneratedHeaderProof{
		PackagePath: fixture.plan.Module + "/pkg", Definitions: definitions,
	}
	if fixture.adjust != nil {
		fixture.adjust(header)
	}
	return header, nil
}

func (fixture *conditionFreePlanningFixture) selectedGoSources(request discoveryFeatureProfileRequest) (map[string]string, error) {
	ctx := fixture.context
	minor, err := discoveryGoMinor(fixture.baseline.GoVersion)
	if err != nil {
		return nil, err
	}
	cpuKey := discoveryCPPFeatureCPUKey(ctx.GOARCH)
	cpu := fixture.baseline.Environment[cpuKey]
	if value, present := request.Overrides[cpuKey]; present {
		cpu = value
	}
	ctx.ToolTags = discoveryModeledCPUFeatures(fixture.baseline.ToolTags, ctx.GOARCH, cpu, minor)
	for tag, enabled := range request.Expected {
		var kept []string
		for _, previous := range ctx.ToolTags {
			if previous != tag {
				kept = append(kept, previous)
			}
		}
		if enabled {
			kept = append(kept, tag)
		}
		ctx.ToolTags = kept
	}
	ctx.BuildTags = request.customTags
	originals := make(map[string]string)
	for _, source := range fixture.plan.Sources {
		if source.SHA256 != discoveryFeatureBytesSHA256([]byte(source.Header)) {
			return nil, fmt.Errorf("query model changed its complete original selection source")
		}
		originals[source.File] = source.Header
	}
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		text, present := originals[file]
		if !present {
			return nil, fmt.Errorf("query model omitted selected original %s", file)
		}
		return io.NopCloser(strings.NewReader(text)), nil
	}
	selected := make(map[string]string)
	for file, text := range originals {
		if path.Dir(file) != path.Dir(fixture.assembly) || !strings.HasSuffix(file, ".go") ||
			strings.HasSuffix(file, "_test.go") {
			continue
		}
		matches, err := ctx.MatchFile(path.Dir(file), path.Base(file))
		if err != nil {
			return nil, err
		}
		if matches {
			selected[file] = text
		}
	}
	if selected["pkg/decl.go"] == "" {
		return nil, fmt.Errorf("query model omitted the complete ordinary Go partner")
	}
	return selected, nil
}

func (fixture *conditionFreePlanningFixture) ordinary(t *testing.T) ([]discoveryFeatureProfileRequest, error) {
	t.Helper()
	fixture.plan.headerPlanningCapture = func(request discoveryFeatureProfileRequest, assembly string, _ []string) (*gotoolprofile.GeneratedHeaderProof, error) {
		return fixture.header(t, request, assembly)
	}
	initial, found, err := planDiscoveryFeaturePair(fixture.context, fixture.baseline, fixture.assembly, "pkg/decl.go")
	if err != nil || !found {
		t.Fatalf("initial whole-source pair: found=%t error=%v", found, err)
	}
	return planDiscoveryCPPFeaturePair(fixture.plan, fixture.context, fixture.baseline,
		fixture.assembly, "pkg/decl.go", initial)
}

func TestCPPConditionFreePlanningQueryCountFiveArchitectures(t *testing.T) {
	for _, target := range conditionFreePlanningTargets {
		t.Run(target, func(t *testing.T) {
			fixture := newConditionFreePlanningFixture(t, target, "// GOAMD64_v3 in a comment is not a CPU token.\n", nil)
			requests, err := fixture.ordinary(t)
			if err != nil || len(requests) != 0 {
				t.Fatalf("condition-free source changed its ordinary branch denominator: %v %+v", err, requests)
			}
			if len(fixture.queries) != 1 {
				t.Fatalf("condition-free source queried %d CPU headers; want one exact original request", len(fixture.queries))
			}
		})
	}
}

func TestCPPConditionFreePlanningKeepsSensitiveGraphQueries(t *testing.T) {
	for _, target := range conditionFreePlanningTargets {
		t.Run(target, func(t *testing.T) {
			arch := strings.Split(target, "/")[1]
			cpu := discoveryCPPFeatureCPUKey(arch)
			cases := []struct {
				name, body string
				extra      map[string]string
			}{
				{"conditional", "#ifdef ABSENT\n#endif\n", nil},
				{"logical line control", "#line 30 \"virtual.s\"\n", nil},
				{"nested include", "#include \"choice.h\"\n", map[string]string{"pkg/choice.h": "#ifdef ABSENT\n#endif\n"}},
				{"object-generated control", "#define SELECT \\\n#ifdef ABSENT \\\n#endif \\\n\nSELECT\n", nil},
				{"formal-generated control", "#define SELECT(P) \\\n#ifdef P \\\n#endif \\\n\nSELECT(ABSENT)\n", nil},
				{"formal include", "#define INCLUDE(P) \\\n#include P \\\n\nINCLUDE(\"choice.h\")\n", map[string]string{"pkg/choice.h": "#define CHOSEN 1\n"}},
				{"unused replacement hash", "#define UNUSED #\n", nil},
				{"unknown candidate", "DATA ·unused(SB)/8,$\"absent.h\"\n", nil},
				{"CPU token", "GLOBL ·cpuMarker(SB),$" + cpu + "_unused\n", nil},
				{"experiment token", "GLOBL ·experimentMarker(SB),$GOEXPERIMENT_unused\n", nil},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					fixture := newConditionFreePlanningFixture(t, target, test.body, test.extra)
					if _, err := fixture.ordinary(t); err != nil {
						t.Fatal(err)
					}
					if len(fixture.queries) != conditionFreePlanningCPUCount(arch) {
						t.Fatalf("sensitive complete source erased queries: got=%d want=%d", len(fixture.queries), conditionFreePlanningCPUCount(arch))
					}
				})
			}
		})
	}
}

func TestCPPConditionFreePlanningKeepsSensitiveHeaderQueries(t *testing.T) {
	for _, target := range conditionFreePlanningTargets {
		t.Run(target, func(t *testing.T) {
			arch := strings.Split(target, "/")[1]
			cpu := discoveryCPPFeatureCPUKey(arch)
			for _, test := range []struct{ name, key, value string }{
				{"unused hash", "const_Unused", "#"},
				{"unused generated control", "const_Unused", "#ifdef ABSENT"},
				{"CPU replacement", "const_Unused", cpu + "_unused"},
				{"CPU definition", cpu + "_unused", "1"},
				{"experiment replacement", "const_Unused", "GOEXPERIMENT_unused"},
				{"experiment definition", "GOEXPERIMENT_unused", "1"},
			} {
				t.Run(test.name, func(t *testing.T) {
					fixture := newConditionFreePlanningFixture(t, target, "", nil)
					// Deliberately adversarial callback values remain query input.
					// Canonical syntax is not evidence of actual compiler origins.
					fixture.adjust = func(header *gotoolprofile.GeneratedHeaderProof) {
						header.Definitions[test.key] = test.value
					}
					if _, err := fixture.ordinary(t); err != nil {
						t.Fatal(err)
					}
					if len(fixture.queries) != conditionFreePlanningCPUCount(arch) {
						t.Fatalf("sensitive canonical header erased CPU queries: got=%d want=%d",
							len(fixture.queries), conditionFreePlanningCPUCount(arch))
					}
				})
			}
		})
	}
}

func TestCPPConditionFreePlanningRetainsFullOriginalGraphGuards(t *testing.T) {
	for _, mutation := range []string{
		"raw bytes", "raw hash", "raw projection", "missing include", "foreign origin",
		"unknown deferred", "callback raw change", "callback include change",
	} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newConditionFreePlanningFixture(t, "linux/amd64",
				"#include \"choice.h\"\n", map[string]string{"pkg/choice.h": "#define CHOSEN 1\n"})
			inputs := fixture.plan.CPPInputs
			root := "module/" + fixture.assembly
			switch mutation {
			case "raw bytes":
				source := inputs.Sources[root]
				changed := *source.Original + "// changed original\n"
				source.Original = &changed
				inputs.Sources[root] = source
			case "raw hash":
				source := inputs.Sources[root]
				source.SHA256 = discoveryFeatureBytesSHA256([]byte("foreign"))
				inputs.Sources[root] = source
			case "raw projection":
				source := inputs.Sources[root]
				source.Directives = source.Directives[1:]
				inputs.Sources[root] = source
			case "missing include":
				delete(inputs.Sources, "module/pkg/choice.h")
			case "foreign origin":
				for key, target := range inputs.Units[0].Includes {
					if target == "module/pkg/choice.h" {
						inputs.Units[0].Includes[key] = "foreign/pkg/choice.h"
					}
				}
			case "unknown deferred":
				for key := range inputs.Units[0].DeferredIncludes {
					inputs.Units[0].DeferredIncludes[key] = "unregistered_header"
				}
			case "callback raw change", "callback include change":
				fixture.adjust = func(_ *gotoolprofile.GeneratedHeaderProof) {
					id := root
					if mutation == "callback include change" {
						id = "module/pkg/choice.h"
					}
					source := inputs.Sources[id]
					changed := *source.Original + "// changed during header query\n"
					source.Original = &changed
					inputs.Sources[id] = source
				}
			}
			if requests, err := fixture.ordinary(t); err == nil {
				t.Fatalf("changed or unbound complete graph gained a planning fast path: %+v", requests)
			}
		})
	}
}

func TestCPPConditionFreePlanningPortableOriginalsDoNotNeedPrivateIndex(t *testing.T) {
	for _, target := range conditionFreePlanningTargets {
		t.Run(target, func(t *testing.T) {
			fixture := newConditionFreePlanningFixture(t, target, "#include \"choice.h\"\n",
				map[string]string{"pkg/choice.h": "#define CHOSEN 1\n"})
			data, err := json.Marshal(fixture.plan.CPPInputs)
			if err != nil {
				t.Fatal(err)
			}
			var restored discoveryCPPInputs
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			fixture.plan.CPPInputs = &restored
			if requests, err := fixture.ordinary(t); err != nil || len(requests) != 0 || len(fixture.queries) != 1 {
				t.Fatalf("complete portable originals changed query-only planning: requests=%+v queries=%d error=%v",
					requests, len(fixture.queries), err)
			}
		})
	}
}

func TestCPPConditionFreePlanningRechecksChangedCompleteOriginals(t *testing.T) {
	for _, target := range conditionFreePlanningTargets {
		t.Run(target, func(t *testing.T) {
			fixture := newConditionFreePlanningFixture(t, target, "#include \"choice.h\"\n",
				map[string]string{"pkg/choice.h": "#define CHOSEN 1\n"})
			if _, err := fixture.ordinary(t); err != nil {
				t.Fatal(err)
			}
			// This is a new complete input, not stale public fields under an
			// old identity. A planning query must re-inspect it on every call.
			text := "#define CHOSEN 1\n#ifdef ABSENT\n#endif\n"
			changed, err := discoveryReplayCPPSource("pkg/choice.h", []byte(text))
			if err != nil {
				t.Fatal(err)
			}
			fixture.plan.CPPInputs.Sources["module/pkg/choice.h"] = changed
			for index := range fixture.plan.Sources {
				if fixture.plan.Sources[index].File == "pkg/choice.h" {
					fixture.plan.Sources[index].Header = text
					fixture.plan.Sources[index].SHA256 = changed.SHA256
				}
			}
			fixture.queries = make(map[string]int)
			if _, err := fixture.ordinary(t); err != nil {
				t.Fatal(err)
			}
			if len(fixture.queries) != conditionFreePlanningCPUCount(fixture.context.GOARCH) {
				t.Fatalf("a prior condition-free query hid new complete controls: queries=%d want=%d",
					len(fixture.queries), conditionFreePlanningCPUCount(fixture.context.GOARCH))
			}
		})
	}
}

func conditionFreePlanningCPUCount(arch string) int {
	// Independent inventory of the current audited legal CPU proposals.
	return map[string]int{"386": 2, "amd64": 4, "arm": 3, "arm64": 32, "wasm": 4}[arch]
}

func TestCPPConditionFreePlanningKeepsInstrumentationExpandedOutput(t *testing.T) {
	for _, target := range conditionFreePlanningTargets {
		t.Run(target, func(t *testing.T) {
			fixture := newConditionFreePlanningFixture(t, target, "GLOBL ·valueMarker(SB),$const_Ordinal\n", nil)
			mode := &discoveryInstrumentationSelectionModel{Mode: gotoolprofile.InstrumentationRace}
			mode.planningHeader = func(request discoveryFeatureProfileRequest, assembly string) (*gotoolprofile.GeneratedHeaderProof, error) {
				header, err := fixture.header(t, request, assembly)
				if err == nil {
					header.Definitions["const_Ordinal"] = strconv.Itoa(fixture.queries[discoveryHeaderPlanningKey(request, assembly, request.customTags)])
				}
				return header, err
			}
			initial, found, err := planDiscoveryFeaturePairWithMode(fixture.context, fixture.baseline, fixture.assembly, "pkg/decl.go", mode)
			if err != nil || !found {
				t.Fatalf("mode pair: found=%t error=%v", found, err)
			}
			requests, err := planDiscoveryCPPFeaturePairWithMode(fixture.plan, fixture.context, fixture.baseline,
				fixture.assembly, "pkg/decl.go", initial, mode)
			if err != nil || len(fixture.queries) != conditionFreePlanningCPUCount(fixture.context.GOARCH) ||
				len(requests) != conditionFreePlanningCPUCount(fixture.context.GOARCH)-1 {
				t.Fatalf("mode lost a full expanded-output variant: queries=%d requests=%d error=%v", len(fixture.queries), len(requests), err)
			}
		})
	}
}

func TestCPPConditionFreePlanningKeepsGoOnlyFeaturePartner(t *testing.T) {
	fixture := newConditionFreePlanningFixture(t, "linux/amd64", "", map[string]string{
		"pkg/feature.go": "//go:build amd64.v3 && goexperiment.fieldtrack\n\npackage fixture\ntype FeatureOnly struct { Value uint32 }\n",
	})
	fixture.plan.headerPlanningCapture = func(request discoveryFeatureProfileRequest, assembly string, _ []string) (*gotoolprofile.GeneratedHeaderProof, error) {
		return fixture.header(t, request, assembly)
	}
	requests, err := planDiscoveryFeatureProfiles(fixture.plan, []string{fixture.assembly}, []*discoveryTargetFeatures{fixture.baseline})
	if err != nil || len(requests) != 2 {
		t.Fatalf("whole Go-source feature denominator: %+v error=%v", requests, err)
	}
	var feature bool
	for _, request := range requests {
		feature = feature || request.Overrides["GOAMD64"] == "v3" && request.Expected["goexperiment.fieldtrack"]
	}
	if !feature {
		t.Fatal("Go-only CPU/experiment partner disappeared behind condition-free ASM")
	}
	var selectedFeature bool
	for _, files := range fixture.selected {
		selectedFeature = selectedFeature || equalDiscoveryStrings(files, []string{"pkg/decl.go", "pkg/feature.go"})
	}
	if !selectedFeature {
		t.Fatal("required Go-only profile lost its complete selected source in the header query model")
	}
	if len(fixture.queries) != 2 {
		t.Fatalf("Go-only partner should query each required original scope once, got=%d", len(fixture.queries))
	}
}
