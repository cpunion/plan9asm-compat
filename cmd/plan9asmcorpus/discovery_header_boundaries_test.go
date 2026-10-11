package main

import (
	"fmt"
	"go/build"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func discoveryHeaderBoundaryContext(sources map[string]string) build.Context {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.Compiler = "linux", "arm64", "gc"
	ctx.CgoEnabled = false
	ctx.BuildTags, ctx.ToolTags, ctx.ReleaseTags = nil, nil, nil
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		source, ok := sources[filepath.Base(file)]
		if !ok {
			return nil, fmt.Errorf("missing original header %s", file)
		}
		return io.NopCloser(strings.NewReader(source)), nil
	}
	return ctx
}

func TestDiscoveryConstraintExpressionRetainsGoHeaderBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
	}{
		{"legacy blank", "// +build alpha\n\npackage p\n"},
		{"legacy no blank", "// +build ignore\npackage p\n"},
		{"legacy BOM", "\ufeff// +build alpha\n\npackage p\n"},
		{"legacy BOM no blank", "\ufeff// +build ignore\npackage p\n"},
		{"legacy partial boundary", "// +build alpha\n\n// +build ignore\npackage p\n"},
		{"legacy conjunction", "// +build alpha\n// +build beta\n\npackage p\n"},
		{"legacy below block", "/* license */\n// +build ignore\n\npackage p\n"},
		{"legacy before block", "// +build alpha\n\n/* license */\n// +build ignore\n\npackage p\n"},
		{"modern no blank", "//go:build alpha\npackage p\n"},
		{"modern after block", "/* license */\n//go:build alpha\npackage p\n"},
		{"modern inside block", "/*\n//go:build ignore\n*/\npackage p\n"},
		{"modern BOM", "\ufeff//go:build alpha\n\npackage p\n"},
		{"modern prefix without separator", "//go:buildignore\n\npackage p\n"},
		{"modern after code", "/* license */ package p\n//go:build ignore\n"},
		{"modern same line after block", "/* license */ //go:build ignore\npackage p\n"},
		{"multiple same-line blocks", "/* license */ /* second */ package p\n//go:build ignore\n"},
		{"modern precedence", "//go:build alpha\n// +build ignore\n\npackage p\n"},
		{"modern with malformed legacy", "//go:build alpha\n// +build alpha?\n\npackage p\n"},
		{"duplicate modern", "//go:build alpha\n//go:build beta\n\npackage p\n"},
		{"duplicate modern across block", "//go:build alpha\n/* license */\n//go:build beta\npackage p\n"},
		{"malformed modern", "//go:build alpha &&\n\npackage p\n"},
		{"malformed legacy", "// +build alpha?\n\npackage p\n"},
		{"empty legacy", "// +build\n\npackage p\n"},
		{"legacy CRLF", "// +build alpha\r\n\r\n// +build ignore\r\npackage p\r\n"},
	} {
		for _, file := range []string{"decl.go", "native.s"} {
			t.Run(test.name+"/"+file, func(t *testing.T) {
				source := test.source
				if file == "native.s" {
					source = strings.ReplaceAll(source, "package p", "TEXT ·F(SB),$0-0\nRET")
				}
				ctx := discoveryHeaderBoundaryContext(map[string]string{file: source})
				expr, exprErr := discoveryFileBuildExpression(filepath.Join("virtual", file), ctx.OpenFile)
				for mask := 0; mask < 8; mask++ {
					var tags []string
					selected := map[string]bool{}
					for bit, tag := range []string{"alpha", "beta", "ignore"} {
						if mask&(1<<bit) != 0 {
							tags = append(tags, tag)
							selected[tag] = true
						}
					}
					ctx.BuildTags = tags
					want, nativeErr := ctx.MatchFile("virtual", file)
					if (exprErr != nil) != (nativeErr != nil) {
						t.Fatalf("tags=%v expression error=%v original Go error=%v", tags, exprErr, nativeErr)
					}
					if nativeErr != nil {
						continue
					}
					got := expr == nil || expr.Eval(func(tag string) bool { return selected[tag] })
					if got != want {
						t.Fatalf("tags=%v expression selection=%v original Go selection=%v", tags, got, want)
					}
				}
			})
		}
	}
}

func TestDiscoveryWideTagLegacyHeaderCannotHideSelectableAssembly(t *testing.T) {
	var tags []string
	for index := 0; index < 17; index++ {
		tags = append(tags, fmt.Sprintf("feature%02d", index))
	}
	assembly := "//go:build " + strings.Join(tags, " || ") + "\n\nTEXT ·F(SB),$0-0\nRET\n"
	for _, declaration := range []string{
		"// +build ignore\npackage p\n",
		"/* license */\n// +build ignore\n\npackage p\n",
		"/* license */ package p\n//go:build ignore\n",
	} {
		t.Run(declaration, func(t *testing.T) {
			ctx := discoveryHeaderBoundaryContext(map[string]string{
				"native_arm64.s": assembly,
				"decl.go":        declaration,
			})
			byFile := map[string][]string{
				filepath.Join("virtual", "native_arm64.s"): tags,
				filepath.Join("virtual", "decl.go"):        {"ignore"},
			}
			if selected, err := discoveryTagSetMatches(ctx, "virtual", "native_arm64.s", "decl.go", tags[:1]); err != nil || !selected {
				t.Fatalf("original Go must select the minimal tag: %v %v", selected, err)
			}
			got, selected, err := findDiscoveryBuildTags(ctx, "virtual", "native_arm64.s", []string{"decl.go"}, tags, byFile)
			if err != nil || !selected || !reflect.DeepEqual(got, tags[:1]) {
				t.Fatalf("wide expression pruning hid an actual Go configuration: tags=%v selected=%v err=%v", got, selected, err)
			}
		})
	}
}

func TestOrdinaryHeaderBoundaryTagExtractionKeepsCompleteDenominator(t *testing.T) {
	for _, test := range []struct {
		name        string
		asmHeader   string
		goHeader    string
		selectedTag string
	}{
		{name: "modern BOM Go", goHeader: "\ufeff//go:build alpha\n\n", selectedTag: "alpha"},
		{name: "legacy BOM Go", goHeader: "\ufeff// +build alpha\n\n", selectedTag: "alpha"},
		{name: "modern BOM ASM", asmHeader: "\ufeff//go:build alpha\n\n", selectedTag: "alpha"},
		{name: "legacy BOM ASM", asmHeader: "\ufeff// +build alpha\n\n", selectedTag: "alpha"},
		{name: "legacy no blank", goHeader: "// +build ignore\n"},
		{name: "legacy after block", goHeader: "/* license */\n// +build ignore\n\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := []string{"native.s"}
			targets := []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"}
			sources := map[string]string{
				"go.mod":   "module example.com/ordinary\n\ngo 1.20\n",
				"native.s": test.asmHeader + "TEXT ·F(SB),$0-0\nRET\n",
				"decl.go":  test.goHeader + "package p\nfunc F()\n",
			}
			plan := fixtureOrdinarySelection(t, files, targets, sources)
			_, selected, err := replayOrdinarySelection(plan, files)
			if err != nil {
				t.Fatal(err)
			}
			var tags []string
			if test.selectedTag != "" {
				tags = []string{test.selectedTag}
			}
			for _, target := range targets {
				if !selected[nativeLayoutKey("native.s", target, tags)] {
					t.Fatalf("actual source tag disappeared from the production denominator: target=%s tags=%v decisions=%+v", target, tags, plan.Decisions)
				}
				goos, goarch, _ := strings.Cut(target, "/")
				ctx := discoveryHeaderBoundaryContext(sources)
				ctx.GOOS, ctx.GOARCH = goos, goarch
				if actual, err := discoveryTagSetMatches(ctx, ".", "native.s", "decl.go", tags); err != nil || !actual {
					t.Fatalf("production selection has no original Go counterpart: target=%s tags=%v selected=%v err=%v", target, tags, actual, err)
				}
			}
			if len(selected) != len(targets) {
				t.Fatalf("added or missing scopes: got %d want %d", len(selected), len(targets))
			}
		})
	}
}
