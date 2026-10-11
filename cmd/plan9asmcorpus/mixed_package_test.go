package main

import (
	"errors"
	"go/build"
	"runtime"
	"strings"
	"testing"
)

func TestMixedPackageCommandRequiresCompleteUniqueDiagnostic(t *testing.T) {
	packages := [2]string{"probe", "probe_x"}
	files := [2]string{"probe.go", "probe_test.go"}
	directory := "original/module/pkg"
	diagnostic := mixedPackageError(directory, packages, files) + "\n"
	if err := validateMixedPackageCommand(directory, packages, files, 1, "", diagnostic); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]string{
		"foreign directory": strings.ReplaceAll(diagnostic, directory, "foreign/module/pkg"),
		"foreign file":      strings.ReplaceAll(diagnostic, "probe_test.go", "foreign.go"),
		"foreign package":   strings.ReplaceAll(diagnostic, "probe_x", "probe_test"),
		"duplicate":         diagnostic + diagnostic,
		"extra source":      diagnostic + "other.go:3: undefined: x\n",
		"infrastructure":    diagnostic + "go: proxy.golang.org: connection refused\n",
		"wrapper":           "wrapper: " + diagnostic,
	} {
		t.Run(name, func(t *testing.T) {
			if validateMixedPackageCommand(directory, packages, files, 1, "", changed) == nil {
				t.Fatal("foreign, partial or mixed diagnostic accepted")
			}
		})
	}
	for _, code := range []int{-1, 0, 2} {
		if validateMixedPackageCommand(directory, packages, files, code, "", diagnostic) == nil {
			t.Fatalf("non-plain source exit %d accepted", code)
		}
	}
	if validateMixedPackageCommand(directory, packages, files, 1, "partial export", diagnostic) == nil {
		t.Fatal("mixed export stdout accepted")
	}
}

func TestMixedPackageSelectionMatchesStockGoDirectoryRoles(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"invalid test name": {"probe_test.go": "package probe_x\n"},
		"ordinary conflict": {"other.go": "package other\n"},
		"three packages": {
			"first.go": "package first\n", "other.go": "package other\n",
			"probe_test.go": "package probe_x\n",
		},
		"valid external test": {"probe_test.go": "package probe_test\n"},
		"valid internal test": {"probe_test.go": "package probe\n"},
		"documentation and ignored files": {
			"probe_test.go": "package probe_x\n", "doc.go": "package documentation\n",
			"_hidden.go": "package hidden\n", ".hidden.go": "package hidden\n",
			"never.go":               "//go:build never\n\npackage never\n",
			"custom_test.go":         "//go:build custom\n\npackage probe_test\n",
			"target_windows_test.go": "package windows_x\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/mixed-roles", Version: "v1.0.0",
				AsmFiles: []string{"probe_amd64.s"}}
			sources := map[string]string{
				"go.mod":   "module example.invalid/mixed-roles\n",
				"probe.go": "package probe\n", "probe_amd64.s": "TEXT ·Probe(SB),$0-0\nRET\n",
			}
			for file, data := range extra {
				sources[file] = data
			}
			download := fixtureProfileModuleDownload(t, candidate, sources)
			plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/amd64"})
			if err != nil {
				t.Fatal(err)
			}
			// Source order is not loader order. The complete sorted directory
			// remains authoritative even if the saved source rows are shuffled.
			for left, right := 0, len(plan.Sources)-1; left < right; left, right = left+1, right-1 {
				plan.Sources[left], plan.Sources[right] = plan.Sources[right], plan.Sources[left]
			}
			for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
				for _, tags := range [][]string{nil, {"custom"}} {
					ctx := build.Default
					ctx.GOOS, ctx.GOARCH, _ = strings.Cut(target, "/")
					ctx.CgoEnabled, ctx.Compiler, ctx.BuildTags = false, "gc", tags
					pkg, originalErr := ctx.ImportDir(download.Dir, 0)
					profile := discoveryFeatureProfile{Observed: &discoveryTargetFeatures{
						Target: target, GoVersion: runtime.Version(), ToolTags: ctx.ToolTags,
					}}
					selection, replayErr := replayMixedPackageSelection(plan, profile, ".", tags)
					var conflict *build.MultiplePackageError
					if !errors.As(originalErr, &conflict) {
						if originalErr != nil || replayErr == nil {
							t.Fatalf("legal original package role became mixed: original=%v replay=%v", originalErr, replayErr)
						}
						continue
					}
					if replayErr != nil || selection.Packages != [2]string{conflict.Packages[0], conflict.Packages[1]} ||
						selection.Files != [2]string{conflict.Files[0], conflict.Files[1]} ||
						!equalDiscoveryStrings(selection.GoFiles, pkg.GoFiles) ||
						!equalDiscoveryStrings(selection.SFiles, pkg.SFiles) ||
						!equalDiscoveryStrings(selection.TestGoFiles, pkg.TestGoFiles) ||
						!equalDiscoveryStrings(selection.XTestGoFiles, pkg.XTestGoFiles) ||
						!equalDiscoveryStrings(selection.IgnoredGoFiles, pkg.IgnoredGoFiles) ||
						!equalDiscoveryStrings(selection.InvalidGoFiles, pkg.InvalidGoFiles) {
						t.Fatalf("complete Go directory roles differ for %s %v: original=%+v replay=%+v err=%v",
							target, tags, pkg, selection, replayErr)
					}
				}
			}
		})
	}
}

func TestMixedPackageProofFailureCannotBecomeGenericSourceNA(t *testing.T) {
	group := discoveryPackageGroup{Pattern: "example.invalid/probe", AsmFiles: []string{"probe.s"}}
	diagnostic := "found packages probe (probe.go) and probe_x (probe_test.go) in original\n"
	for _, output := range []string{diagnostic, diagnostic + "other.go:3: undefined: x\n"} {
		failure := &discoveryCapturedCommandError{
			command: "go list -export", cause: errors.New("fixture original failure"), output: output,
		}
		called := false
		_, err := runDiscoveryPackageChecksWithProof([]discoveryPackageGroup{group},
			func([]string) error { return failure }, func(actual discoveryPackageGroup, err error) (bool, error) {
				called = true
				if actual.Pattern != group.Pattern || !isPotentialMixedPackageFailure(err) {
					t.Fatal("mixed-package proof lost its package attribution")
				}
				return false, errors.New("fixture incomplete typed proof")
			})
		if err == nil || !called {
			t.Fatal("incomplete positionless proof bypassed strict rejection")
		}
	}
}

func TestMixedPackageSelectionRejectsUnmodeledSourceRoles(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"selected cgo":       {"cgo.go": "package probe\nimport \"C\"\n"},
		"test cgo":           {"cgo_test.go": "package probe\nimport \"C\"\n"},
		"ignored bad name":   {"never.go": "//go:build never\n\npackage\n"},
		"ignored bad import": {"never.go": "//go:build never\n\npackage probe\nimport (\n"},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/mixed-invalid", Version: "v1.0.0",
				AsmFiles: []string{"probe_amd64.s"}}
			sources := map[string]string{
				"go.mod":   "module example.invalid/mixed-invalid\n",
				"probe.go": "package probe\n", "probe_test.go": "package probe_x\n",
				"probe_amd64.s": "TEXT ·Probe(SB),$0-0\nRET\n",
			}
			for file, data := range extra {
				sources[file] = data
			}
			download := fixtureProfileModuleDownload(t, candidate, sources)
			plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/amd64"})
			if err != nil {
				// Invalid import-selection prefixes are already rejected at
				// capture. They must never be manufactured into a valid proof.
				if name == "ignored bad import" && strings.Contains(err.Error(), "capture original Go import selection never.go:") {
					return
				}
				t.Fatalf("unexpected fixture/source-capture failure: %v", err)
			}
			profile := discoveryFeatureProfile{Observed: &discoveryTargetFeatures{
				Target: "linux/amd64", GoVersion: runtime.Version(), ToolTags: build.Default.ToolTags,
			}}
			if _, err := replayMixedPackageSelection(plan, profile, ".", nil); err == nil {
				t.Fatal("unmodeled cgo or malformed target-ignored source became typed N/A")
			}
		})
	}
}
