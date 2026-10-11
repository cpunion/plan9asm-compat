package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoveryAsmDeclPaddedArgsRequiresExactSelectedMetadata(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sqrt.s")
	packages := []discoveryGoListPackage{{ImportPath: "example.com/padded", Dir: dir, SFiles: []string{"sqrt.s"}}}
	for _, test := range []struct {
		name, source, filename, arch, declared, expected string
		ignored                                          bool
	}{
		{"amd64", "TEXT ·Sqrt(SB),$0-16", "sqrt.s:1", "amd64", "16", "12", true},
		{"386", "TEXT ·Sqrt(SB),$0-8", "sqrt.s:1", "386", "8", "5", true},
		{"arm", "TEXT ·Sqrt(SB),$0-8", "sqrt.s:1", "arm", "8", "5", true},
		{"arm64", "TEXT ·Sqrt(SB),$0-16", "sqrt.s:1", "arm64", "16", "12", true},
		{"wasm source word", "TEXT ·Sqrt(SB),$0-16", "sqrt.s:1", "wasm", "16", "12", true},
		{"ABI0 selector", "TEXT ·Sqrt<ABI0>(SB),$0-16", "sqrt.s:1", "amd64", "16", "12", true},
		{"ABIInternal is not ABI0", "TEXT ·Sqrt<ABIInternal>(SB),$0-16", "sqrt.s:1", "amd64", "16", "12", false},
		{"extra aligned word", "TEXT ·Sqrt(SB),$0-24", "sqrt.s:1", "amd64", "24", "12", false},
		{"not aligned", "TEXT ·Sqrt(SB),$0-15", "sqrt.s:1", "amd64", "15", "12", false},
		{"stale size", "TEXT ·Sqrt(SB),$0-24", "sqrt.s:1", "amd64", "16", "12", false},
		{"omitted", "TEXT ·Sqrt(SB),$0", "sqrt.s:1", "amd64", "16", "12", false},
		{"zero", "TEXT ·Sqrt(SB),$0-0", "sqrt.s:1", "amd64", "16", "12", false},
		{"different symbol", "TEXT ·Other(SB),$0-16", "sqrt.s:1", "amd64", "16", "12", false},
		{"wrong line", "TEXT ·Sqrt(SB),$0-16", "sqrt.s:2", "amd64", "16", "12", false},
		{"unselected", "TEXT ·Sqrt(SB),$0-16", "foreign/sqrt.s:1", "amd64", "16", "12", false},
		{"macro", "TEXT ·Sqrt(SB),$0-ARGS", "sqrt.s:1", "amd64", "16", "12", false},
		{"expression", "TEXT ·Sqrt(SB),$0-(8+8)", "sqrt.s:1", "amd64", "16", "12", false},
		{"unknown arch", "TEXT ·Sqrt(SB),$0-16", "sqrt.s:1", "unknown", "16", "12", false},
		{"overflow", "TEXT ·Sqrt(SB),$0-9223372036854775808", "sqrt.s:1", "amd64", "9223372036854775808", "12", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeTestFile(t, file, test.source+"\nRET\n")
			warning := fmt.Sprintf("%s: [%s] Sqrt: wrong argument size %s; expected $...-%s",
				test.filename, test.arch, test.declared, test.expected)
			got := filterDiscoveryAsmDeclTextMetadataLines([]string{warning}, packages, "")
			if (len(got) == 0) != test.ignored {
				t.Fatalf("remaining=%v, want ignored=%t", got, test.ignored)
			}
		})
	}

	writeTestFile(t, file, "TEXT ·Sqrt(SB),$0-16\nRET\n")
	warning := "sqrt.s:1: [amd64] Sqrt: wrong argument size 16; expected $...-12"
	for _, diagnostic := range []string{
		"sqrt.s:3: [amd64] Sqrt: invalid offset r+12(FP); expected r+8(FP)",
		"sqrt.s:3: [amd64] Sqrt: invalid MOVSD of r+8(FP); float32 is 4-byte value",
		"go: unknown failure after inspecting TEXT metadata",
	} {
		if got := filterDiscoveryAsmDeclTextMetadataLines([]string{warning, diagnostic}, packages, ""); !reflect.DeepEqual(got, []string{diagnostic}) {
			t.Fatalf("padding exception hid another error: %v", got)
		}
	}
	foreign := []string{"# example.com/foreign", warning}
	if got := filterDiscoveryAsmDeclTextMetadataLines(foreign, packages, ""); !reflect.DeepEqual(got, foreign) {
		t.Fatalf("foreign warning removed: %v", got)
	}
	other := t.TempDir()
	writeTestFile(t, filepath.Join(other, "sqrt.s"), "TEXT ·Sqrt(SB),$0-16\nRET\n")
	ambiguous := append(packages, discoveryGoListPackage{ImportPath: "example.com/other", Dir: other, SFiles: []string{"sqrt.s"}})
	if got := filterDiscoveryAsmDeclTextMetadataLines([]string{warning}, ambiguous, ""); !reflect.DeepEqual(got, []string{warning}) {
		t.Fatalf("ambiguous basename removed: %v", got)
	}
}

func TestRunDiscoveryAsmDeclAcceptsABI0TailPadding(t *testing.T) {
	for _, symbol := range []string{"Sqrt", "Sqrt+0"} {
		t.Run(symbol, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/padded\n\ngo 1.20\n")
			writeTestFile(t, filepath.Join(dir, "sqrt.go"), "package padded\n\nfunc Sqrt(x float32) (r float32)\n")
			writeTestFile(t, filepath.Join(dir, "sqrt_amd64.s"),
				"TEXT ·"+symbol+"(SB),$0-16\nSQRTSS x+0(FP),X0\nMOVSS X0,r+8(FP)\nRET\n")
			env := replaceEnv(os.Environ(), map[string]string{
				"GOFLAGS": "-mod=mod", "GOWORK": "off", "CGO_ENABLED": "0",
				"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1",
			})
			if err := runDiscoveryGoBuild(context.Background(), dir, env, "linux/amd64", nil, "example.com/padded"); err != nil {
				t.Fatalf("actual Go assembler rejected original padded TEXT: %v", err)
			}
			_, raw := runCapturedCommandOutput(context.Background(), dir, env, "go", "vet", "-asmdecl", "example.com/padded")
			want := "wrong argument size 16; expected $...-12"
			if symbol == "Sqrt+0" {
				want = "function Sqrt+0 missing Go declaration"
			}
			if raw == nil || !strings.Contains(discoveryCommandDiagnostic(raw), want) {
				t.Fatalf("actual asmdecl false positive not reproduced (%s): %v", want, raw)
			}
			if err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/amd64", nil, []string{"example.com/padded"}); err != nil {
				t.Fatalf("Go-accepted source was excluded: %v", err)
			}
		})
	}
}

func TestRunDiscoveryAsmDeclPaddedArgsPreservesRealABIError(t *testing.T) {
	for _, test := range []struct{ name, body, diagnostic string }{
		{"wrong result", "MOVSS X0,r+12(FP)", "invalid offset"},
		{"wide result", "MOVSD X0,r+8(FP)", "invalid MOVSD"},
		{"wide input", "SQRTSD x+0(FP),X0\nMOVSS X0,r+8(FP)", "invalid SQRTSD"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/padded\n\ngo 1.20\n")
			writeTestFile(t, filepath.Join(dir, "sqrt.go"), "package padded\nfunc Sqrt(x float32) (r float32)\n")
			writeTestFile(t, filepath.Join(dir, "sqrt_amd64.s"), "TEXT ·Sqrt(SB),$0-16\n"+test.body+"\nRET\n")
			env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off"})
			err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/amd64", nil, []string{"example.com/padded"})
			if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), test.diagnostic) {
				t.Fatalf("real ABI diagnostic was hidden: %v", err)
			}
		})
	}
}
