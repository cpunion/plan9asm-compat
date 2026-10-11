package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoveryAsmDeclUnspecifiedArgsRequiresSelectedLiteralText(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "decl_amd64.s")
	packages := []discoveryGoListPackage{{
		ImportPath: "example.com/literal", Dir: dir, SFiles: []string{"decl_amd64.s"},
	}}
	for _, test := range []struct {
		name, source, reported string
		ignored                bool
	}{
		{"omitted", "TEXT ·Value(SB),$0\nRET\n", "decl_amd64.s:1:1", true},
		{"zero", "TEXT ·Value(SB),$0-0\nRET\n", "decl_amd64.s:1", true},
		{"frame and zero", "TEXT ·Value(SB),$32-0 // legacy metadata\nRET\n", "decl_amd64.s:1:1", true},
		{"literal flags", "TEXT ·Value(SB),4|NOSPLIT,$0\nRET\n", "decl_amd64.s:1:1", true},
		{"abi selector", "TEXT ·Value<ABI0>(SB),$0\nRET\n", "decl_amd64.s:1:1", true},
		{"absolute selected path", "TEXT ·Value(SB),$0\nRET\n", file + ":1:1", true},
		{"nonzero args", "TEXT ·Value(SB),$0-8\nRET\n", "decl_amd64.s:1:1", false},
		{"different symbol", "TEXT ·Other(SB),$0\nRET\n", "decl_amd64.s:1:1", false},
		{"wrong line", "TEXT ·Value(SB),$0\nRET\n", "decl_amd64.s:2:1", false},
		{"out of range line", "TEXT ·Value(SB),$0\nRET\n", "decl_amd64.s:20:1", false},
		{"unselected path", "TEXT ·Value(SB),$0\nRET\n", "foreign/decl_amd64.s:1:1", false},
		{"macro frame", "TEXT ·Value(SB),$FRAME\nRET\n", "decl_amd64.s:1:1", false},
		{"expression args", "TEXT ·Value(SB),$0-(8)\nRET\n", "decl_amd64.s:1:1", false},
		{"block comment", "/* TEXT ·Value(SB),$0 */\nRET\n", "decl_amd64.s:1:1", false},
		{"block license", "/* license\n * comment\n */\nTEXT ·Value(SB),$0\nRET\n", "decl_amd64.s:4:1", true},
		{"inline block comment", "TEXT /* flags omitted */ ·Value(SB),$0\nRET\n", "decl_amd64.s:1:1", true},
		{"string delimiter", "DATA ·str<>+0(SB)/4,$\"/*//\"\nTEXT ·Value(SB),$0\nRET\n", "decl_amd64.s:2:1", true},
		{"unterminated comment", "TEXT ·Value(SB),$0\n/*\n", "decl_amd64.s:1:1", false},
		{"multiple statements", "TEXT ·Value(SB),$0; RET\n", "decl_amd64.s:1:1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeTestFile(t, file, test.source)
			warning := test.reported + ": [amd64] Value: wrong argument size 0; expected $...-1"
			got := filterDiscoveryAsmDeclTextMetadataLines([]string{warning}, packages, "")
			if (len(got) == 0) != test.ignored {
				t.Fatalf("filtered = %v, want ignored=%v", got, test.ignored)
			}
		})
	}
}

func TestDiscoveryAsmDeclUnspecifiedArgsPreservesOtherABIAndUnknownFailures(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Value(SB),$0\nRET\n")
	packages := []discoveryGoListPackage{{ImportPath: "example.com/literal", Dir: dir, SFiles: []string{"decl_amd64.s"}}}
	zero := "decl_amd64.s:1:1: [amd64] Value: wrong argument size 0; expected $...-1"
	for _, diagnostic := range []string{
		"decl_amd64.s:3:1: [amd64] Other: wrong argument size 16; expected $...-8",
		"decl_amd64.s:4:1: [amd64] Value: invalid offset ret+4(FP); expected ret+0(FP)",
		"decl_amd64.s:5:1: [amd64] Value: invalid MOVQ of ret+0(FP); bool is 1-byte value",
		"go: type checker failed before completing analysis",
	} {
		if got := filterDiscoveryAsmDeclTextMetadataLines([]string{zero, diagnostic}, packages, ""); !reflect.DeepEqual(got, []string{diagnostic}) {
			t.Fatalf("remaining diagnostics = %v, want %q", got, diagnostic)
		}
	}
	foreign := []string{"# example.com/foreign", zero}
	if got := filterDiscoveryAsmDeclTextMetadataLines(foreign, packages, ""); !reflect.DeepEqual(got, foreign) {
		t.Fatalf("foreign warning was removed: %v", got)
	}
	otherDir := t.TempDir()
	writeTestFile(t, filepath.Join(otherDir, "decl_amd64.s"), "TEXT ·Value(SB),$0\nRET\n")
	packages = append(packages, discoveryGoListPackage{ImportPath: "example.com/other", Dir: otherDir, SFiles: []string{"decl_amd64.s"}})
	if got := filterDiscoveryAsmDeclTextMetadataLines([]string{zero}, packages, ""); !reflect.DeepEqual(got, []string{zero}) {
		t.Fatalf("ambiguous basename warning was removed: %v", got)
	}
	if got := filterDiscoveryAsmDeclTextMetadataLines([]string{"# [example.com/literal]", zero}, packages, ""); !reflect.DeepEqual(got, []string{"# [example.com/literal]"}) {
		t.Fatalf("package-qualified warning not resolved: %v", got)
	}
}

func TestDiscoveryAsmDeclUnspecifiedArgsSourceLookupFailureCannotBecomeNA(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/empty\n\ngo 1.20\n")
	failure := &discoveryCapturedCommandError{
		directory: dir,
		command:   "go vet -asmdecl", cause: discoveryAsmDeclObservedExitOne(t),
		output: "decl_amd64.s:1:1: [amd64] Value: wrong argument size 0; expected $...-1\n",
	}
	env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off", "GOPROXY": "off"})
	err := filterDiscoveryAsmDeclTextMetadata(context.Background(), dir, env, nil, []string{"./missing"}, "", failure)
	if !errors.Is(err, errDiscoveryAsmDeclSourceProof) || !isDiscoveryInfrastructureFailure(err) {
		t.Fatalf("missing source metadata became ABI N/A: %v", err)
	}
	if !strings.Contains(discoveryCommandDiagnostic(err), "wrong argument size 0") {
		t.Fatalf("original failure evidence was lost: %v", err)
	}
}

func TestRunDiscoveryAsmDeclUnspecifiedArgsDoesNotHideRealABIError(t *testing.T) {
	for _, test := range []struct {
		name, frame, instruction, diagnostic string
	}{
		{"nonzero size", "$0-16", "MOVB $1, ret+0(FP)", "wrong argument size 16"},
		{"omitted with offset", "$0", "MOVB $1, ret+4(FP)", "invalid offset"},
		{"zero with width", "$0-0", "MOVQ $1, ret+0(FP)", "invalid MOVQ"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "work")
			module := filepath.Join(root, "module")
			for _, path := range []string{dir, module} {
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			writeTestFile(t, filepath.Join(dir, "go.mod"),
				"module plan9asm.local/probe\n\ngo 1.20\n\nrequire example.com/invalidabi v0.0.0\nreplace example.com/invalidabi => ../module\n")
			writeTestFile(t, filepath.Join(module, "go.mod"), "module example.com/invalidabi\n\ngo 1.20\n")
			writeTestFile(t, filepath.Join(module, "decl.go"), "package invalidabi\n\nfunc Value() bool\n")
			writeTestFile(t, filepath.Join(module, "decl_amd64.s"),
				"TEXT ·Value(SB),"+test.frame+"\n"+test.instruction+"\nRET\n")
			writeTestFile(t, filepath.Join(module, "decl_test.go"), "package invalidabi\n\nvar _ int = false\n")
			env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off"})
			err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/amd64", nil, []string{"example.com/invalidabi"})
			if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), test.diagnostic) {
				t.Fatalf("real ABI diagnostic hidden after testless retry: %v, want %q", err, test.diagnostic)
			}
			if test.name != "nonzero size" && strings.Contains(discoveryCommandDiagnostic(err), "wrong argument size 0") {
				t.Fatalf("staged unspecified-args warning was not filtered before cleanup: %v", err)
			}
		})
	}
}

func TestRunDiscoveryAsmDeclUnspecifiedArgsWorksWithoutTestFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/withouttests\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package withouttests\n\nfunc Value() bool\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Value(SB),$0\nMOVB $1, ret+0(FP)\nRET\n")
	env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off"})
	if err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/amd64", nil, []string{"example.com/withouttests"}); err != nil {
		t.Fatalf("unspecified args with no testless retry candidate: %v", err)
	}
}
