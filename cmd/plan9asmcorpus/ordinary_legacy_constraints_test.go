package main

import (
	"context"
	"encoding/json"
	"go/build"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOrdinaryLegacyConstraintSpellingsPreserveActualGoSelection(t *testing.T) {
	for _, prefix := range []string{"//+build", "// +build", "//\t+build", "//    +build"} {
		t.Run(prefix, func(t *testing.T) {
			header := prefix + " !nopshufb\n\n// original documentation\n"
			compact := compactOrdinarySelectionHeader(header)
			for _, tags := range [][]string{nil, {"nopshufb"}} {
				ctx := build.Default
				ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = "darwin", "amd64", "gc", false
				ctx.BuildTags = tags
				match := func(source string) bool {
					ctx.OpenFile = func(string) (io.ReadCloser, error) {
						return io.NopCloser(strings.NewReader(source)), nil
					}
					selected, err := ctx.MatchFile(".", "galois_amd64.s")
					if err != nil {
						t.Fatal(err)
					}
					return selected
				}
				if original, captured := match(header), match(compact); original != captured {
					t.Fatalf("original selection %t became %t for tags %v: %q", original, captured, tags, compact)
				}
			}
			expression, err := discoveryFileBuildExpression("galois_amd64.s", func(string) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(compact)), nil
			})
			if err != nil || expression == nil || expression.String() != "!nopshufb" {
				t.Fatalf("legal legacy constraint lost from custom-tag proposals: %v, %v", expression, err)
			}
		})
	}
}

func TestOrdinaryConstraintProposalUsesGoConstraintTokens(t *testing.T) {
	for _, source := range []string{"//+buildx ignore\n\n", "// go:build ignore\n\n", "//documentation +build ignore\n\n"} {
		expression, err := discoveryFileBuildExpression("probe.s", func(string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(source)), nil
		})
		if err != nil || expression != nil {
			t.Fatalf("ordinary comment became a build constraint: %q: %v, %v", source, expression, err)
		}
	}
	for _, source := range []string{"//go:build\tfeature && !ignore\r\n\r\n", "//\t+build feature,!ignore\r\n\r\n"} {
		expression, err := discoveryFileBuildExpression("probe.s", func(string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(source)), nil
		})
		if err != nil || expression == nil || expression.String() != "feature && !ignore" {
			t.Fatalf("legal whitespace/combination disappeared: %q: %v, %v", source, expression, err)
		}
	}
}

func TestOrdinaryLegacyConstraintPackageScopesMatchStockGo(t *testing.T) {
	dir := t.TempDir()
	for file, source := range map[string]string{
		"go.mod":                      "module example.com/legacyconstraints\n\ngo 1.20\n",
		"decl.go":                     "package legacyconstraints\nfunc original()\nfunc generated()\n",
		"galois_amd64.s":              "//+build !nopshufb\n\nTEXT ·original(SB),4,$0-0\nRET\n",
		"galois_gen_amd64.s":          "//go:build !nopshufb\n\nTEXT ·generated(SB),4,$0-0\nRET\n",
		"galois_gen_nopshufb_amd64.s": "//go:build nopshufb\n\nTEXT ·generated(SB),4,$0-0\nRET\n",
	} {
		writeTestFile(t, filepath.Join(dir, file), source)
	}
	candidate := discoveryCandidate{
		Module: "example.com/legacyconstraints", Version: "v1.0.0",
		AsmFiles: []string{"galois_amd64.s", "galois_gen_amd64.s", "galois_gen_nopshufb_amd64.s"},
	}
	plan, err := captureOrdinarySelectionInputs(candidate, dir, []string{"darwin/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	_, selected, err := replayOrdinarySelection(plan, candidate.AsmFiles)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "darwin/amd64", nil)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	_, err = closeOrdinaryPackageTagScopes(plan, candidate.AsmFiles, nil, selected, actual)
	if err != nil {
		t.Fatal(err)
	}
	for _, tags := range [][]string{nil, {"nopshufb"}} {
		var planned []string
		for _, file := range candidate.AsmFiles {
			if selected[nativeLayoutKey(file, "darwin/amd64", tags)] {
				planned = append(planned, file)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		args := []string{"list", "-mod=readonly", "-json"}
		if len(tags) != 0 {
			args = append(args, "-tags="+strings.Join(tags, ","))
		}
		command := exec.CommandContext(ctx, "go", append(args, ".")...)
		command.Dir = dir
		command.Env = replaceEnv(os.Environ(), map[string]string{"GOOS": "darwin", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOFLAGS": "", "GOWORK": "off"})
		output, err := command.Output()
		cancel()
		if err != nil {
			t.Fatalf("stock Go source selection: %v: %s", err, output)
		}
		var stock struct{ SFiles []string }
		if err := json.Unmarshal(output, &stock); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(planned, stock.SFiles) {
			t.Fatalf("tags %v: planned %v, actual Go %v", tags, planned, stock.SFiles)
		}
	}
}
