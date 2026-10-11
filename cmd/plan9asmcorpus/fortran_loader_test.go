package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/build"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestFortranLoaderRequiresCompleteExactDiagnostic(t *testing.T) {
	files := []string{"a.f", "b.f90"}
	wanted := "package example.invalid/probe: Fortran source files not allowed when not using cgo or SWIG: a.f b.f90\n"
	if err := validateFortranLoaderCommand("example.invalid/probe", files, 1, "", wanted); err != nil {
		t.Fatal(err)
	}
	for name, diagnostic := range map[string]string{
		"missing file":         strings.ReplaceAll(wanted, " b.f90", ""),
		"foreign package":      strings.ReplaceAll(wanted, "example.invalid/probe", "other.invalid/probe"),
		"duplicate":            wanted + wanted,
		"extra compiler error": wanted + "other.go:3: undefined: x\n",
		"network failure":      wanted + "go: proxy.golang.org: connection refused\n",
		"substring":            "wrapper: " + wanted,
	} {
		t.Run(name, func(t *testing.T) {
			if validateFortranLoaderCommand("example.invalid/probe", files, 1, "", diagnostic) == nil {
				t.Fatal("incomplete, foreign or mixed loader diagnostic accepted")
			}
		})
	}
	for _, code := range []int{-1, 0, 2} {
		if validateFortranLoaderCommand("example.invalid/probe", files, code, "", wanted) == nil {
			t.Fatalf("unexpected process exit %d accepted", code)
		}
	}
	if validateFortranLoaderCommand("example.invalid/probe", files, 1, "partial export", wanted) == nil {
		t.Fatal("mixed export stdout accepted")
	}
}

func TestFortranLoaderSelectionHeadersMatchStockGo(t *testing.T) {
	contents := map[string]string{
		"bom.f":           "\ufeff//go:build custom\n\nPROGRAM original\nEND\n",
		"semicolon.f":     ";\t// license\n//go:build custom\n\nPROGRAM original\nEND\n",
		"inline.f":        "/* license */ //go:build custom\n\nPROGRAM original\nEND\n",
		"nul.f":           "//go:build custom\n\n\x00PROGRAM original\nEND\n",
		"comment-nul.f":   "// original\x00comment\n//go:build custom\n\nPROGRAM original\nEND\n",
		"bad-comment.f":   "/* unterminated source\n",
		"bad-slash.f":     "/=PROGRAM original\nEND\n",
		"a.f":             "PROGRAM original\nEND\n",
		"b.F":             "//go:build custom\n\nPROGRAM original\nEND\n",
		"c.for":           "//+build !custom\n\nPROGRAM original\nEND\n",
		"d.f90":           "//  +build\tcustom\r\n\r\nPROGRAM original\r\nEND\r\n",
		"e_linux.f":       "/* license\n//go:build never\n*/\nPROGRAM original\nEND\n",
		"f_windows.F":     "//go:build windows\n\nPROGRAM original\nEND\n",
		"g.f":             "//+build never\nPROGRAM original\nEND\n", // no legacy blank line
		"h.f90":           "// +buildx never\n\nPROGRAM original\nEND\n",
		"i.f":             "//go:build custom && (linux || darwin)\n\nPROGRAM original\nEND\n",
		"j.f":             "//go:build custom\n", // EOF control
		"_hidden.f":       "PROGRAM original\nEND\n",
		".hidden.F":       "PROGRAM original\nEND\n",
		"unsupported.F90": "PROGRAM original\nEND\n",
	}
	for _, target := range []string{"linux/amd64", "darwin/arm64", "windows/386"} {
		for _, tags := range [][]string{nil, {"custom"}} {
			for name, data := range contents {
				file := "pkg/" + name
				input, err := fortranSelectionInput(file, []byte(data))
				if err != nil {
					t.Fatal(err)
				}
				if input.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(data))) {
					t.Fatal("selection header replaced the original full source hash")
				}
				ctx := build.Default
				ctx.GOOS, ctx.GOARCH, _ = strings.Cut(target, "/")
				ctx.CgoEnabled, ctx.BuildTags = false, tags
				selectFile := func(source string) (bool, error) {
					ctx.OpenFile = func(actual string) (io.ReadCloser, error) {
						if filepath.ToSlash(actual) != file {
							return nil, fmt.Errorf("foreign file %s", actual)
						}
						return io.NopCloser(strings.NewReader(source)), nil
					}
					return ctx.MatchFile("pkg", name)
				}
				original, originalErr := selectFile(data)
				captured, capturedErr := selectFile(input.Header)
				if original != captured || fmt.Sprint(originalErr) != fmt.Sprint(capturedErr) {
					t.Fatalf("Go MatchFile changed for %s %v %s: original=%t %v header=%t %v", target, tags, name, original, originalErr, captured, capturedErr)
				}
			}
		}
	}
}

func TestFortranLoaderProofFailureCannotBecomeGenericSourceNA(t *testing.T) {
	group := discoveryPackageGroup{Pattern: "example.invalid/probe", AsmFiles: []string{"probe.s"}}
	for name, diagnostic := range map[string]string{
		"loader only":                 "package example.invalid/probe: Fortran source files not allowed when not using cgo or SWIG: a.f\n",
		"mixed concrete source error": "package example.invalid/probe: Fortran source files not allowed when not using cgo or SWIG: a.f\nother.go:3: undefined: x\n",
	} {
		t.Run(name, func(t *testing.T) {
			failure := &discoveryCapturedCommandError{command: "go list -export", cause: errors.New("fixture source failure"), output: diagnostic}
			called := false
			_, err := runDiscoveryPackageChecksWithProof([]discoveryPackageGroup{group}, func([]string) error { return failure },
				func(actual discoveryPackageGroup, sourceErr error) (bool, error) {
					called = true
					if actual.Pattern != group.Pattern || !isPotentialFortranLoaderFailure(group.Pattern, sourceErr) {
						t.Fatal("typed loader attribution lost its exact package")
					}
					return false, fmt.Errorf("fixture incomplete typed proof")
				})
			if err == nil || !called {
				t.Fatal("mixed/no-position loader failure bypassed typed proof validation")
			}
		})
	}
}

func TestFortranLoaderExtensionFamily(t *testing.T) {
	for _, name := range []string{"a.f", "a.F", "a.for", "a.f90", "_hidden.f", ".hidden.f"} {
		if !isDiscoveryFortranFile(name) {
			t.Fatalf("Go Fortran extension omitted: %s", name)
		}
	}
	for _, name := range []string{"a.f95", "a.F90", "a.FOR", "a.c", "a.s", "a.f.go"} {
		if isDiscoveryFortranFile(name) {
			t.Fatalf("non-Go Fortran extension accepted: %s", name)
		}
	}
}
