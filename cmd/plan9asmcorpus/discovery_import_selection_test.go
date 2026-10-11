package main

import (
	"go/build"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryImportCSelectionMatchesGo(t *testing.T) {
	for _, tc := range []struct {
		name, source string
	}{
		{"plain", "package probe\nimport \"C\"\n"},
		{"grouped alias", "package probe\nimport (\n c \"C\"\n \"unsafe\"\n)\n"},
		{"escaped", "package probe\nimport \"\\x43\"\n"},
		{"ordinary", "package probe\nimport \"fmt\"\n"},
		{"comment is not import", "package probe\n// import \"C\"\nvar text = `import \"C\"`\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, source := range map[string]string{"decl.go": tc.source, "native_arm64.s": "TEXT ·F(SB),$0-0\nRET\n"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, cgo := range []bool{false, true} {
				ctx := build.Default
				ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = "linux", "arm64", "gc", cgo
				pkg, err := ctx.ImportDir(dir, 0)
				if err != nil {
					if _, noGo := err.(*build.NoGoError); !noGo {
						t.Fatal(err)
					}
				}
				want := len(pkg.GoFiles) != 0 || cgo && len(pkg.CgoFiles) != 0
				_, got, err := findDiscoveryBuildTags(ctx, dir, "native_arm64.s", []string{"decl.go"}, nil, nil)
				if err != nil || got != want {
					t.Errorf("CGO_ENABLED=%v: discovery=%v/%v, GoFiles=%v CgoFiles=%v IgnoredGoFiles=%v", cgo, got, err, pkg.GoFiles, pkg.CgoFiles, pkg.IgnoredGoFiles)
				}
			}
		})
	}
}

func TestDiscoveryImportCSelectionReplayAndValidSibling(t *testing.T) {
	const cgoSource = "//go:build feature\n\npackage probe\n/* native preamble */\nimport (\n c \"C\"\n \"unsafe\"\n)\nfunc notRetained() {}\n"
	input, err := nativeLayoutSourceInputFromBytes("decl.go", []byte(cgoSource))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(input.Header, "c \"C\"") || strings.Contains(input.Header, "notRetained") {
		t.Fatalf("source replay must preserve original import declarations but not bodies: %q", input.Header)
	}
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = "linux", "arm64", "gc", false
	contents := map[string]string{"decl.go": input.Header, "native_arm64.s": "", "ordinary.go": "package probe\n"}
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(contents[filepath.Base(file)])), nil
	}
	tags := map[string][]string{filepath.Join("virtual", "decl.go"): {"feature"}}
	for _, goFiles := range [][]string{{"decl.go"}, {"decl.go", "ordinary.go"}} {
		_, selected, err := findDiscoveryBuildTags(ctx, "virtual", "native_arm64.s", goFiles, []string{"feature"}, tags)
		if err != nil || selected != (len(goFiles) == 2) {
			t.Fatalf("captured source-only replay: files=%v selected=%v err=%v", goFiles, selected, err)
		}
	}
	plan := fixtureOrdinarySelection(t, []string{"native_arm64.s"}, []string{"linux/arm64"}, map[string]string{
		"native_arm64.s": "TEXT ·F(SB),$0-0\nRET\n", "decl.go": cgoSource,
	})
	if len(plan.Decisions) != 1 || plan.Decisions[0].Kind != ordinarySelectionCgoDisabled {
		t.Fatalf("original import C must replay as explicit cgo-disabled scope: %+v", plan.Decisions)
	}
}

func TestDiscoveryImportSelectionFailsClosed(t *testing.T) {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = "linux", "arm64", "gc", false
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		data := ""
		if strings.HasSuffix(file, ".go") {
			data = "package probe\nimport ( broken\n"
		}
		return io.NopCloser(strings.NewReader(data)), nil
	}
	if _, _, err := findDiscoveryBuildTags(ctx, "virtual", "native_arm64.s", []string{"decl.go"}, nil, nil); err == nil {
		t.Fatal("malformed import evidence must fail, not turn into a pass or source N/A")
	}
}
