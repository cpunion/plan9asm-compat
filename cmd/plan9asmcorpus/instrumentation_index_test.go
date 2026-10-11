package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// This test-only reference freezes the denominator algorithm at aba5f1d0.
// It is deliberately not an alternate producer, reader or trusted JSON index.
type legacyInstrumentationWork struct {
	sourceVisits, packageClauses, headerReads int
}

func legacyInstrumentationGoPartners(contents map[string][]byte, dir string, work *legacyInstrumentationWork) []string {
	var files []string
	for name, source := range contents {
		work.sourceVisits++
		if path.Dir(name) != dir || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(path.Base(name), ".") || strings.HasPrefix(path.Base(name), "_") {
			continue
		}
		work.packageClauses++
		if _, err := parser.ParseFile(token.NewFileSet(), name, source, parser.PackageClauseOnly); err == nil {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files
}

func legacyInstrumentationRequirements(plan *discoveryOrdinarySelectionPlan, files []string, baselines []*discoveryTargetFeatures, work *legacyInstrumentationWork) ([]discoveryInstrumentationRequirement, error) {
	if plan == nil || len(baselines) != len(plan.Targets) {
		return nil, fmt.Errorf("mode planning requires every actual target baseline")
	}
	contents := make(map[string][]byte)
	for _, source := range plan.Sources {
		if _, duplicate := contents[source.File]; duplicate {
			return nil, fmt.Errorf("duplicate mode selection source")
		}
		contents[source.File] = []byte(source.Header)
	}
	byKey := make(map[string]*discoveryInstrumentationRequirement)
	seenTargets := make(map[string]bool)
	for _, baseline := range baselines {
		if baseline == nil || baseline.GoVersion != plan.GoVersion || seenTargets[baseline.Target] || !containsTargetFeature(plan.Targets, baseline.Target) {
			return nil, fmt.Errorf("mode planning has a missing, duplicate or foreign baseline")
		}
		seenTargets[baseline.Target] = true
		ctx, err := discoveryContextForFeatureProfile(baseline)
		if err != nil {
			return nil, err
		}
		ctx.OpenFile = func(file string) (io.ReadCloser, error) {
			work.headerReads++
			data, found := contents[filepath.ToSlash(file)]
			if !found {
				return nil, fmt.Errorf("uncaptured original mode source: %s", file)
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		for _, asmFile := range files {
			if _, found := contents[asmFile]; !found {
				return nil, fmt.Errorf("missing original mode assembly source")
			}
			dir := path.Dir(asmFile)
			if discoveryDirIsIgnored(dir) || discoveryFeatureNestedSource(plan, dir) || ordinarySelectionPackagePathError(plan.Module, dir) != nil {
				continue
			}
			for _, goFile := range legacyInstrumentationGoPartners(contents, dir, work) {
				mentioned, cgoMentioned, err := legacyInstrumentationPairTags(ctx, asmFile, goFile)
				if err != nil {
					return nil, err
				}
				for _, mode := range []gotoolprofile.InstrumentationMode{gotoolprofile.InstrumentationRace, gotoolprofile.InstrumentationMSan, gotoolprofile.InstrumentationASan} {
					if !mentioned[string(mode)] {
						continue
					}
					cgovalues := []bool{true}
					if cgoMentioned {
						cgovalues = append(cgovalues, false)
					}
					for _, cgo := range cgovalues {
						request, found, err := planDiscoveryFeaturePairWithMode(ctx, baseline, asmFile, goFile, &discoveryInstrumentationSelectionModel{Mode: mode, CGO: cgo})
						if err != nil {
							return nil, fmt.Errorf("mode source pair %s + %s on %s/%s: %w", asmFile, goFile, baseline.Target, mode, err)
						}
						if !found {
							continue
						}
						required, err := discoveryInstrumentationPairRequired(ctx, baseline, request, asmFile, goFile, cgo)
						if err != nil {
							return nil, err
						}
						if !required {
							continue
						}
						r := discoveryInstrumentationRequirement{
							BaselineID: discoveryFeatureProfileID(baseline), Target: baseline.Target, Mode: mode,
							CGO: "1", Directory: dir, Tags: request.customTags, Overrides: request.Overrides, Expected: request.Expected,
						}
						if !cgo {
							r.CGO = "0"
						}
						if len(r.Overrides) == 0 {
							r.Overrides = nil
						}
						keyData, err := json.Marshal(r)
						if err != nil {
							return nil, err
						}
						key := string(keyData)
						if byKey[key] == nil {
							copy := r
							byKey[key] = &copy
						}
						byKey[key].Pairs = append(byKey[key].Pairs, [2]string{asmFile, goFile})
						if len(byKey) > 256 {
							return nil, fmt.Errorf("source-required instrumentation scopes exceed the explicit 256-scope bound")
						}
					}
				}
			}
		}
	}
	result := make([]discoveryInstrumentationRequirement, 0, len(byKey))
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		r := *byKey[key]
		data, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		r.ID = discoveryFeatureBytesSHA256(data)
		result = append(result, r)
	}
	return result, nil
}

func instrumentationIndexModelFixture(assembly, unrelated int) (*discoveryOrdinarySelectionPlan, []string, []*discoveryTargetFeatures) {
	// This is a pure source-predicate benchmark, not an actual tool/export proof.
	baseline := &discoveryTargetFeatures{
		GoVersion: runtime.Version(), Target: "linux/amd64",
		Environment:     map[string]string{"GOAMD64": "v1"},
		MarkerSelection: map[string]bool{"amd64.v1": true, "amd64.v2": false, "amd64.v3": false, "amd64.v4": false},
	}
	plan := &discoveryOrdinarySelectionPlan{
		Module: "example.invalid/index-model", Version: "v1.0.0",
		GoVersion: baseline.GoVersion, Targets: []string{baseline.Target},
	}
	var files []string
	for index := 0; index < assembly; index++ {
		name := fmt.Sprintf("pkg/probe%03d_amd64.s", index)
		files = append(files, name)
		plan.Sources = append(plan.Sources, ordinarySelectionSource{File: name, Header: "//go:build race\n\n"})
	}
	for index := 0; index < 2; index++ {
		name := fmt.Sprintf("pkg/declaration%03d.go", index)
		plan.Sources = append(plan.Sources, ordinarySelectionSource{File: name, Header: "//go:build race\n\npackage probe\n"})
	}
	for index := 0; index < unrelated; index++ {
		name := fmt.Sprintf("unrelated/dir%03d/file.go", index)
		plan.Sources = append(plan.Sources, ordinarySelectionSource{File: name, Header: "package unrelated\n"})
	}
	return plan, files, []*discoveryTargetFeatures{baseline}
}

func TestInstrumentationPlannerBaselineRepeatedSourceWork(t *testing.T) {
	for _, test := range []struct{ assembly, unrelated int }{{1, 128}, {16, 128}, {16, 4096}} {
		plan, files, baselines := instrumentationIndexModelFixture(test.assembly, test.unrelated)
		work := &legacyInstrumentationWork{}
		reference, err := legacyInstrumentationRequirements(plan, files, baselines, work)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := planDiscoveryInstrumentationRequirements(plan, files, baselines)
		if err != nil || !reflect.DeepEqual(actual, reference) {
			t.Fatalf("same-input denominator differs: %v", err)
		}
		if work.sourceVisits != len(plan.Sources)*len(files) || work.packageClauses != 2*len(files) {
			t.Fatalf("baseline work no longer follows its frozen source loop: %+v", work)
		}
		data, err := json.Marshal(actual)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("sources=%d asm=%d source_visits=%d package_clauses=%d header_reads=%d result_sha256=%s", len(plan.Sources), len(files), work.sourceVisits, work.packageClauses, work.headerReads, discoveryFeatureBytesSHA256(data))
	}
}

func legacyInstrumentationPairTags(ctx build.Context, files ...string) (map[string]bool, bool, error) {
	all := make(map[string]bool)
	for _, file := range files {
		expr, err := discoveryFileBuildExpression(filepath.FromSlash(file), ctx.OpenFile)
		if err != nil {
			return nil, false, err
		}
		if expr != nil {
			collectDiscoveryConstraintTags(expr, all)
		}
	}
	return all, all["cgo"], nil
}

func TestInstrumentationSourceIndexBoundsWorkWithoutCrossCallReuse(t *testing.T) {
	plan, files, baselines := instrumentationIndexModelFixture(16, 4096)
	index, err := newDiscoveryInstrumentationSourceIndex(plan, files)
	if err != nil {
		t.Fatal(err)
	}
	indexed, err := planDiscoveryInstrumentationRequirementsIndexed(plan, files, baselines, index)
	if err != nil {
		t.Fatal(err)
	}
	work := &legacyInstrumentationWork{}
	reference, err := legacyInstrumentationRequirements(plan, files, baselines, work)
	if err != nil || !reflect.DeepEqual(indexed, reference) {
		t.Fatalf("indexed predicate changed the frozen denominator: %v", err)
	}
	if len(index.contents) != len(plan.Sources) || len(index.directories) != 1 ||
		len(index.clauses) != 2 || len(index.expressions) != len(files)+2 {
		t.Fatalf("index lost its once-per-call source/Go-clause/constraint bound: sources=%d directories=%d clauses=%d expressions=%d", len(index.contents), len(index.directories), len(index.clauses), len(index.expressions))
	}
	t.Logf("same-input baseline source_visits=%d package_clauses=%d; index source_visits=%d package_clauses=%d constraint_parses=%d", work.sourceVisits, work.packageClauses, len(index.contents), len(index.clauses), len(index.expressions))

	// A new replay must read new source predicates, not a source/hash/provenance
	// memo or an index stored in the plan or report.
	for position := range plan.Sources {
		if strings.HasPrefix(plan.Sources[position].File, "pkg/") {
			plan.Sources[position].Header = strings.ReplaceAll(plan.Sources[position].Header, "race", "asan")
		}
	}
	changed, err := planDiscoveryInstrumentationRequirements(plan, files, baselines)
	if err != nil || reflect.DeepEqual(changed, indexed) || len(changed) != 1 || changed[0].Mode != gotoolprofile.InstrumentationASan {
		t.Fatalf("another replay borrowed cached original predicates: %+v %v", changed, err)
	}
	if plan.InstrumentationPlan != nil {
		t.Fatal("source index was persisted as a trusted result")
	}
}

func TestInstrumentationSourceIndexMatchesFrozenGrammarAndErrors(t *testing.T) {
	tests := []struct {
		name   string
		change func(*discoveryOrdinarySelectionPlan, *[]string, *[]*discoveryTargetFeatures)
	}{
		{"default CGO1", func(*discoveryOrdinarySelectionPlan, *[]string, *[]*discoveryTargetFeatures) {}},
		{"complete empty", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			for position := range p.Sources {
				p.Sources[position].Header = strings.ReplaceAll(p.Sources[position].Header, "//go:build race\n\n", "")
			}
		}},
		{"explicit CGO0 and custom tags", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			for position := range p.Sources {
				p.Sources[position].Header = strings.ReplaceAll(p.Sources[position].Header, "race", "race && !cgo && custom")
			}
		}},
		{"all exclusive modes and CGO scopes", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			for position := range p.Sources {
				p.Sources[position].Header = strings.ReplaceAll(p.Sources[position].Header, "race", "(race || msan || asan) && (cgo || !cgo)")
			}
		}},
		{"negated instrumentation", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[1].Header = "//go:build !race && !msan && !asan\n\npackage probe\n"
		}},
		{"CPU and experiment overrides", func(p *discoveryOrdinarySelectionPlan, _ *[]string, b *[]*discoveryTargetFeatures) {
			(*b)[0].MarkerSelection["goexperiment.fieldtrack"] = false
			for position := range p.Sources {
				p.Sources[position].Header = strings.ReplaceAll(p.Sources[position].Header, "race", "race && amd64.v3 && goexperiment.fieldtrack")
			}
		}},
		{"unknown CPU", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "//go:build race && amd64.v99\n\n"
		}},
		{"release exclusion", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "//go:build race && go1.99\n\n"
		}},
		{"malformed modern directive", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "//go:build race &&\n\n"
		}},
		{"duplicate modern directive", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "//go:build race\n//go:build msan\n\n"
		}},
		{"BOM before modern directive", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "\ufeff//go:build race\n\n"
			p.Sources[1].Header = "\ufeff//go:build race\n\npackage probe\n"
		}},
		{"legacy tab and CRLF", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "//\t+build   race,!cgo\r\n\r\n"
		}},
		{"legacy malformed ignored", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "// +build race,&&\n\n"
		}},
		{"lookalike is not a constraint", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "// +buildx race\n\n"
		}},
		{"late block comment directive ignored", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = "/* comment */ TEXT\n//go:build race &&\n"
		}},
		{"missing original assembly", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources = p.Sources[1:]
		}},
		{"duplicate original source", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources = append(p.Sources, p.Sources[0])
		}},
		{"duplicate assembly input preserved", func(_ *discoveryOrdinarySelectionPlan, f *[]string, _ *[]*discoveryTargetFeatures) {
			*f = append(*f, (*f)[0])
		}},
		{"scanner limit remains an error", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].Header = strings.Repeat("/", 4<<20) + "\n"
		}},
		{"bad package clause", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			for position := 1; position < len(p.Sources); position++ {
				p.Sources[position].Header = "//go:build race\n\npackage ?\n"
			}
		}},
		{"test and hidden partners", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[1].File = "pkg/probe_test.go"
			p.Sources[2].File = "pkg/_probe.go"
		}},
		{"filename impossible malformed still rejected", func(p *discoveryOrdinarySelectionPlan, f *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources[0].File = "pkg/probe_arm64.s"
			(*f)[0] = p.Sources[0].File
			p.Sources[0].Header = "//go:build race &&\n\n"
		}},
		{"unvisited unrelated malformed stays unvisited", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources = append(p.Sources, ordinarySelectionSource{File: "other/bad.go", Header: "//go:build race &&\n\npackage other\n"})
		}},
		{"ignored directory does not parse constraints", func(p *discoveryOrdinarySelectionPlan, f *[]string, _ *[]*discoveryTargetFeatures) {
			for position := range p.Sources {
				p.Sources[position].File = strings.Replace(p.Sources[position].File, "pkg/", "_pkg/", 1)
				p.Sources[position].Header = "//go:build race &&\n\npackage bad\n"
			}
			(*f)[0] = p.Sources[0].File
		}},
		{"nested module does not parse constraints", func(p *discoveryOrdinarySelectionPlan, _ *[]string, _ *[]*discoveryTargetFeatures) {
			p.Directories = []ordinarySelectionDirectory{{Directory: "pkg", Entries: []ordinarySelectionEntry{{Name: "go.mod", Kind: "file"}}}}
			p.Sources[0].Header = "//go:build race &&\n\n"
		}},
		{"ancestor nested module", func(p *discoveryOrdinarySelectionPlan, f *[]string, _ *[]*discoveryTargetFeatures) {
			for position := range p.Sources {
				p.Sources[position].File = strings.Replace(p.Sources[position].File, "pkg/", "ancestor/pkg/", 1)
			}
			(*f)[0] = p.Sources[0].File
			p.Directories = []ordinarySelectionDirectory{{Directory: "ancestor", Entries: []ordinarySelectionEntry{{Name: "go.mod", Kind: "file"}}}}
		}},
		{"invalid package path does not parse constraints", func(p *discoveryOrdinarySelectionPlan, f *[]string, _ *[]*discoveryTargetFeatures) {
			for position := range p.Sources {
				p.Sources[position].File = strings.Replace(p.Sources[position].File, "pkg/", "pkg@invalid/", 1)
			}
			(*f)[0] = p.Sources[0].File
			p.Sources[0].Header = "//go:build race &&\n\n"
		}},
		{"empty files", func(_ *discoveryOrdinarySelectionPlan, f *[]string, _ *[]*discoveryTargetFeatures) { *f = nil }},
		{"missing target", func(_ *discoveryOrdinarySelectionPlan, _ *[]string, b *[]*discoveryTargetFeatures) { *b = nil }},
		{"foreign target", func(_ *discoveryOrdinarySelectionPlan, _ *[]string, b *[]*discoveryTargetFeatures) {
			(*b)[0].Target = "other/amd64"
		}},
		{"wrong Go version", func(_ *discoveryOrdinarySelectionPlan, _ *[]string, b *[]*discoveryTargetFeatures) {
			(*b)[0].GoVersion = "go1.99.1"
		}},
		{"nil baseline", func(_ *discoveryOrdinarySelectionPlan, _ *[]string, b *[]*discoveryTargetFeatures) { (*b)[0] = nil }},
		{"duplicate target baseline", func(p *discoveryOrdinarySelectionPlan, _ *[]string, b *[]*discoveryTargetFeatures) {
			p.Targets = append(p.Targets, p.Targets[0])
			*b = append(*b, (*b)[0])
		}},
		{"scope limit remains an error", func(p *discoveryOrdinarySelectionPlan, f *[]string, _ *[]*discoveryTargetFeatures) {
			p.Sources, *f = nil, nil
			for index := 0; index < 257; index++ {
				dir := fmt.Sprintf("scope%03d", index)
				asm, goFile := dir+"/probe.s", dir+"/probe.go"
				*f = append(*f, asm)
				p.Sources = append(p.Sources,
					ordinarySelectionSource{File: asm, Header: "//go:build race\n\n"},
					ordinarySelectionSource{File: goFile, Header: "//go:build race\n\npackage probe\n"})
			}
		}},
		{"all five architectures", func(p *discoveryOrdinarySelectionPlan, _ *[]string, b *[]*discoveryTargetFeatures) {
			p.Targets, *b = nil, nil
			for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
				target := "linux/" + arch
				if arch == "wasm" {
					target = "js/wasm"
				}
				p.Targets = append(p.Targets, target)
				*b = append(*b, &discoveryTargetFeatures{Target: target, GoVersion: p.GoVersion,
					Environment: map[string]string{"GO386": "sse2", "GOAMD64": "v1", "GOARM": "7"}})
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, files, baselines := instrumentationIndexModelFixture(1, 0)
			test.change(plan, &files, &baselines)
			reference, referenceErr := legacyInstrumentationRequirements(plan, files, baselines, &legacyInstrumentationWork{})
			actual, actualErr := planDiscoveryInstrumentationRequirements(plan, files, baselines)
			if (referenceErr == nil) != (actualErr == nil) ||
				referenceErr != nil && referenceErr.Error() != actualErr.Error() ||
				!reflect.DeepEqual(reference, actual) {
				t.Fatalf("indexed grammar/error differs from frozen stock-source replay:\nreference=%+v error=%v\nactual=%+v error=%v", reference, referenceErr, actual, actualErr)
			}
		})
	}
}

func TestInstrumentationSourceIndexKeepsLazyConstraintErrors(t *testing.T) {
	plan, files, _ := instrumentationIndexModelFixture(1, 0)
	plan.Sources[0].Header = "//go:build race &&\n\n"
	index, err := newDiscoveryInstrumentationSourceIndex(plan, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.expressions) != 0 || len(index.clauses) != 0 {
		t.Fatal("index eagerly parsed original predicates before their requested scope")
	}
	_, first := index.expression(files[0])
	_, second := index.expression(files[0])
	if first == nil || second != first || len(index.expressions) != 1 {
		t.Fatal("same-call malformed constraint was lost or reparsed")
	}
	_, missing := index.expression("pkg/missing.go")
	if missing == nil || !strings.Contains(missing.Error(), "uncaptured original mode source") {
		t.Fatal("missing original source became an empty expression")
	}
}

func BenchmarkInstrumentationDenominatorSameInput(b *testing.B) {
	for _, test := range []struct{ assembly, unrelated int }{{1, 128}, {16, 128}, {16, 4096}} {
		b.Run(fmt.Sprintf("asm%d_sources%d", test.assembly, test.unrelated), func(b *testing.B) {
			plan, files, baselines := instrumentationIndexModelFixture(test.assembly, test.unrelated)
			reference, err := legacyInstrumentationRequirements(plan, files, baselines, &legacyInstrumentationWork{})
			if err != nil {
				b.Fatal(err)
			}
			for _, implementation := range []struct {
				name string
				plan func() ([]discoveryInstrumentationRequirement, error)
			}{
				{
					name: "baseline",
					plan: func() ([]discoveryInstrumentationRequirement, error) {
						return legacyInstrumentationRequirements(plan, files, baselines, &legacyInstrumentationWork{})
					},
				},
				{
					name: "indexed",
					plan: func() ([]discoveryInstrumentationRequirement, error) {
						return planDiscoveryInstrumentationRequirements(plan, files, baselines)
					},
				},
			} {
				b.Run(implementation.name, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for index := 0; index < b.N; index++ {
						actual, err := implementation.plan()
						if err != nil || !reflect.DeepEqual(actual, reference) {
							b.Fatalf("same-input denominator differs: %v", err)
						}
					}
				})
			}
		})
	}
}
