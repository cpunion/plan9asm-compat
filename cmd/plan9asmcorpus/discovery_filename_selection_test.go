package main

import (
	"errors"
	"fmt"
	"go/build"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func countedDiscoverySelectionContext(goos, goarch string, sources map[string]string) (build.Context, map[string]int) {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = goos, goarch, "gc", false
	ctx.BuildTags, ctx.ToolTags = nil, nil
	reads := make(map[string]int)
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		name := filepath.Base(file)
		reads[name]++
		source, ok := sources[name]
		if !ok {
			return nil, fmt.Errorf("missing original input %s", name)
		}
		return io.NopCloser(strings.NewReader(source)), nil
	}
	return ctx, reads
}

func TestDiscoveryFilenameSelectionMatchesStockGo(t *testing.T) {
	for _, target := range []struct{ goos, goarch string }{
		{"linux", "386"}, {"linux", "amd64"}, {"linux", "arm"}, {"linux", "arm64"}, {"js", "wasm"},
		{"android", "arm64"}, {"ios", "arm64"}, {"illumos", "amd64"},
	} {
		for _, allFiles := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/all=%v", target.goos, target.goarch, allFiles), func(t *testing.T) {
				ctx := build.Default
				ctx.GOOS, ctx.GOARCH = target.goos, target.goarch
				ctx.UseAllFiles, ctx.CgoEnabled = allFiles, false
				ctx.BuildTags, ctx.ToolTags = nil, []string{"filename_witness"}
				ctx.OpenFile = func(file string) (io.ReadCloser, error) {
					source := ""
					if strings.HasSuffix(file, ".go") {
						source = "package original\n"
					}
					return io.NopCloser(strings.NewReader(source)), nil
				}
				for _, name := range []string{
					"decl.go", "linux.go", "decl_linux.go", "decl_darwin.go", "decl_solaris.go",
					"decl_windows_arm64.go", "decl_386.go", "decl_amd64.go", "decl_arm.go", "decl_arm64.go", "decl_wasm.go",
					"_decl.go", ".decl.go", "native.s", "native_amd64_test.s", "native_arm64.s", "native_custom.s",
				} {
					want, wantErr := ctx.MatchFile("virtual", name)
					got, err := discoveryFilenameMayMatch(ctx, "virtual", name, nil)
					if err != nil || wantErr != nil || got != want {
						t.Fatalf("%s: filename predicate=%v/%v original Go=%v/%v", name, got, err, want, wantErr)
					}
				}
			})
		}
	}

	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.ToolTags = "linux", "arm64", []string{"windows"}
	if selected, err := discoveryFilenameMayMatch(ctx, "virtual", "decl_windows.go", nil); err != nil || !selected {
		t.Fatalf("exact ToolTags must not be dropped: %v %v", selected, err)
	}
	ctx.ToolTags = nil
	if selected, err := discoveryFilenameMayMatch(ctx, "virtual", "decl_windows.go", []string{"windows"}); err != nil || !selected {
		t.Fatalf("all potential search tags must overapproximate filename predicates: %v %v", selected, err)
	}
}

func TestDiscoveryFilenameDirectSolverPreservesAssemblyErrors(t *testing.T) {
	for _, source := range []string{
		"//go:build feature\n//go:build other\n\nTEXT ·F(SB),$0-0\nRET\n",
		"//go:build feature &&\n\nTEXT ·F(SB),$0-0\nRET\n",
	} {
		ctx, _ := countedDiscoverySelectionContext("linux", "arm64", map[string]string{
			"native_arm64.s":  source,
			"decl_windows.go": "package p\n",
		})
		if _, _, err := solveDiscoveryPairTags(ctx, "virtual", "native_arm64.s", "decl_windows.go", []string{"feature"}, 1); err == nil {
			t.Fatal("Go filename pruning must not hide the direct solver's original ASM header error")
		}
	}
	readErr := errors.New("original ASM read failed")
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH = "linux", "arm64"
	ctx.OpenFile = func(string) (io.ReadCloser, error) { return nil, readErr }
	if _, _, err := solveDiscoveryPairTags(ctx, "virtual", "native_arm64.s", "decl_windows.go", []string{"feature"}, 1); !errors.Is(err, readErr) {
		t.Fatalf("original ASM read failure must retain its error chain: %v", err)
	}
}

// Exhaust only these small test inputs against original MatchFile/import
// selection. This reference deliberately performs no filename precheck and no
// approximate expression pruning, independently retaining size/lex ordering.
func unprunedDiscoveryTagReference(ctx build.Context, dir, asmFile string, goFiles, customTags []string, byFile map[string][]string) ([]string, bool, error) {
	ctx.BuildTags = nil
	asmMatches, err := ctx.MatchFile(dir, asmFile)
	if err != nil {
		return nil, false, err
	}
	if asmMatches {
		for _, goFile := range goFiles {
			matches, err := discoveryGoFileMatches(ctx, dir, goFile)
			if err != nil || matches {
				return nil, matches, err
			}
		}
	}
	var best []string
	for _, goFile := range goFiles {
		pair := discoveryPairTags(byFile[filepath.Join(dir, asmFile)], byFile[filepath.Join(dir, goFile)], customTags)
		if len(pair) > 8 {
			return nil, false, fmt.Errorf("test reference bound exceeded")
		}
		var candidates [][]string
		for mask := 1; mask < 1<<len(pair); mask++ {
			var selected []string
			for bit, tag := range pair {
				if mask&(1<<bit) != 0 {
					selected = append(selected, tag)
				}
			}
			candidates = append(candidates, selected)
		}
		sort.Slice(candidates, func(i, j int) bool {
			if len(candidates[i]) != len(candidates[j]) {
				return len(candidates[i]) < len(candidates[j])
			}
			return discoveryTagsLexicallyBefore(candidates[i], candidates[j])
		})
		for _, tags := range candidates {
			if len(best) != 0 && len(tags) > len(best) {
				break
			}
			selected, err := discoveryTagSetMatches(ctx, dir, asmFile, goFile, tags)
			if err != nil {
				return nil, false, err
			}
			if selected {
				if len(best) == 0 || len(tags) < len(best) || len(tags) == len(best) && discoveryTagsLexicallyBefore(tags, best) {
					best = tags
				}
				break
			}
		}
	}
	return best, len(best) != 0, nil
}

func TestDiscoveryFilenameSelectionKeepsMinimumTagsAndCgo(t *testing.T) {
	for _, test := range []struct {
		name, assembly, declaration string
		cgo                         bool
	}{
		{"lexical tie", "//go:build alpha || beta\n\n", "//go:build alpha || beta\n\npackage p\n", false},
		{"two tags", "//go:build alpha && beta\n\n", "//go:build beta\n\npackage p\n", false},
		{"legacy blank line", "// +build alpha\n\n", "// +build beta\n\npackage p\n", false},
		{"legacy no blank line", "// +build alpha\n", "// +build beta\npackage p\n", false},
		{"negation", "//go:build !alpha && beta\n\n", "//go:build beta || gamma\n\npackage p\n", false},
		{"disabled cgo", "//go:build alpha\n\n", "//go:build alpha\n\npackage p\nimport \"C\"\n", false},
		{"enabled cgo", "//go:build alpha\n\n", "//go:build alpha\n\npackage p\nimport \"C\"\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sources := map[string]string{
				"native_arm64.s":  test.assembly + "TEXT ·F(SB),$0-0\nRET\n",
				"decl_arm64.go":   test.declaration,
				"decl_windows.go": "//go:build alpha || beta || gamma\n\npackage p\n",
			}
			ctx, _ := countedDiscoverySelectionContext("linux", "arm64", sources)
			ctx.CgoEnabled = test.cgo
			byFile := map[string][]string{}
			for file := range sources {
				byFile[filepath.Join("virtual", file)] = []string{"alpha", "beta", "gamma"}
			}
			goFiles := []string{"decl_windows.go", "decl_arm64.go"}
			custom := []string{"alpha", "beta", "gamma"}
			want, wantSelected, wantErr := unprunedDiscoveryTagReference(ctx, "virtual", "native_arm64.s", goFiles, custom, byFile)
			got, selected, err := findDiscoveryBuildTags(ctx, "virtual", "native_arm64.s", goFiles, custom, byFile)
			if err != nil || wantErr != nil || selected != wantSelected || !reflect.DeepEqual(got, want) {
				t.Fatalf("original stock Go reference=%v/%v/%v optimized=%v/%v/%v", want, wantSelected, wantErr, got, selected, err)
			}
		})
	}
}

func BenchmarkDiscoveryFilenameSelection(b *testing.B) {
	const asmFile = "native_arm64.s"
	goFiles := []string{"decl_amd64.go", "decl_windows.go", ".hidden.go", "_ignored.go"}
	sources := map[string]string{asmFile: "//go:build feature\n\nTEXT ·F(SB),$0-0\nRET\n"}
	byFile := map[string][]string{}
	custom := []string{"a", "b", "c", "feature"}
	for _, file := range append(append([]string(nil), goFiles...), asmFile) {
		byFile[filepath.Join("virtual", file)] = custom
		if file != asmFile {
			sources[file] = "//go:build a || b || c || feature\n\npackage p\n"
		}
	}
	for _, test := range []struct {
		name string
		find func(build.Context, string, string, []string, []string, map[string][]string) ([]string, bool, error)
	}{
		{"unpruned_same_input", unprunedDiscoveryTagReference},
		{"filename_pruned_same_input", findDiscoveryBuildTags},
	} {
		b.Run(test.name, func(b *testing.B) {
			ctx, reads := countedDiscoverySelectionContext("linux", "arm64", sources)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, selected, err := test.find(ctx, "virtual", asmFile, goFiles, custom, byFile); err != nil || selected {
					b.Fatalf("unexpected same-input outcome: %v %v", selected, err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(reads[asmFile])/float64(b.N), "original-header-reads/op")
		})
	}
}

func TestDiscoveryFilenameSelectionPrunesBeforeTagSearch(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			otherArch := "amd64"
			if arch == otherArch {
				otherArch = "arm64"
			}
			asmFile := "native_" + arch + ".s"
			goFiles := []string{"decl_" + otherArch + ".go", "decl_windows.go", ".hidden.go", "_ignored.go"}
			sources := map[string]string{asmFile: "//go:build feature\n\nTEXT ·F(SB),$0-0\nRET\n"}
			tagsByFile := map[string][]string{filepath.Join("virtual", asmFile): {"a", "b", "c", "feature"}}
			for _, name := range goFiles {
				sources[name] = "//go:build a || b || c || feature\n\npackage p\n"
				tagsByFile[filepath.Join("virtual", name)] = []string{"a", "b", "c", "feature"}
			}
			ctx, reads := countedDiscoverySelectionContext("linux", arch, sources)
			tags, selected, err := findDiscoveryBuildTags(ctx, "virtual", asmFile, goFiles, []string{"a", "b", "c", "feature"}, tagsByFile)
			if err != nil || selected || len(tags) != 0 {
				t.Fatalf("filename-incompatible partners: tags=%v selected=%v err=%v", tags, selected, err)
			}
			if reads[asmFile] != 1 {
				t.Fatalf("filename-only rejection must leave only the original baseline header read; got %d", reads[asmFile])
			}
			for _, name := range goFiles {
				if reads[name] != 0 {
					t.Fatalf("stock Go must not open filename-incompatible source %s: %d", name, reads[name])
				}
			}
		})
	}
}

func TestDiscoveryFilenameSelectionPreservesMalformedAndOriginalInputs(t *testing.T) {
	for _, test := range []struct {
		name, assembly, declaration string
	}{
		{
			name:        "duplicate go build assembly",
			assembly:    "//go:build a\n//go:build b\n\nTEXT ·F(SB),$0-0\nRET\n",
			declaration: "package p\n",
		},
		{
			name:        "malformed assembly constraint",
			assembly:    "//go:build a &&\n\nTEXT ·F(SB),$0-0\nRET\n",
			declaration: "package p\n",
		},
		{
			name:        "duplicate go build Go",
			assembly:    "TEXT ·F(SB),$0-0\nRET\n",
			declaration: "//go:build a\n//go:build b\n\npackage p\n",
		},
		{
			name:        "malformed imports",
			assembly:    "TEXT ·F(SB),$0-0\nRET\n",
			declaration: "package p\nimport ( broken\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _ := countedDiscoverySelectionContext("linux", "arm64", map[string]string{
				"native_arm64.s": test.assembly,
				"decl_arm64.go":  test.declaration,
			})
			_, _, err := findDiscoveryBuildTags(ctx, "virtual", "native_arm64.s", []string{"decl_arm64.go"}, []string{"a", "b"}, nil)
			if err == nil {
				t.Fatal("original selected-source error must remain a failure")
			}
		})
	}

	sources := map[string]string{
		"native_arm64.s": "//go:build alpha || beta\n\nTEXT ·F(SB),$0-0\nRET\n",
		"decl_arm64.go":  "//go:build alpha || beta\n\npackage p\n",
	}
	ctx, reads := countedDiscoverySelectionContext("linux", "arm64", sources)
	byFile := map[string][]string{
		filepath.Join("virtual", "native_arm64.s"): {"alpha", "beta"},
		filepath.Join("virtual", "decl_arm64.go"):  {"alpha", "beta"},
	}
	tags, selected, err := findDiscoveryBuildTags(ctx, "virtual", "native_arm64.s", []string{"decl_arm64.go"}, []string{"alpha", "beta"}, byFile)
	if err != nil || !selected || !reflect.DeepEqual(tags, []string{"alpha"}) || reads["decl_arm64.go"] == 0 {
		t.Fatalf("actual headers/minimum lexical tags were not consumed: %v %v %v reads=%v", tags, selected, err, reads)
	}
	sources["decl_arm64.go"] = "package p\nimport ( broken\n"
	if _, _, err := findDiscoveryBuildTags(ctx, "virtual", "native_arm64.s", []string{"decl_arm64.go"}, []string{"alpha", "beta"}, byFile); err == nil {
		t.Fatal("a later source mutation must not reuse prior filename or header acceptance")
	}
}
