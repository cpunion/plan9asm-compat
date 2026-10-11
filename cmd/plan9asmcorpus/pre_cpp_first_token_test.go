package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreCPPFirstStatementTokenMatchesGoParserGrammar(t *testing.T) {
	for _, token := range []string{".", ":", "(", ")", "[", "]", "$", "%", "?", "42", "1.5", "\"text\"", "'x'"} {
		t.Run(token, func(t *testing.T) {
			source := "// Original foreign dialect sample.\n/* license */\n" + token + " operand\n"
			err := preCPPSourceSyntax("foreign.s", []byte(source))
			var unsupported *discoveryUnsupportedCPPError
			if !errors.As(err, &unsupported) || unsupported.File != "foreign.s" || unsupported.Line != 3 ||
				unsupported.SHA256 != discoveryFeatureBytesSHA256([]byte(source)) || unsupported.Directive != token {
				t.Fatalf("first non-identifier lacks its exact original Go parser rejection: token=%q error=%v", token, err)
			}
			prefix, err := preCPPControlPrefix([]byte(source), unsupported.Line)
			if err != nil || prefix != source {
				t.Fatalf("first-token source boundary changed: %q %v", prefix, err)
			}
		})
	}
}

func TestPreCPPFirstTokenNeverClaimsPriorControlsOrLexicalErrors(t *testing.T) {
	for _, source := range []string{
		"#ifdef NEVER\n.section .text\n#endif\n",
		"#define SECTION TEXT\n.section .text\n",
		"#include \"unbound.h\"\n.section .text\n",
		"#line 90 \"other.s\"\n.section .text\n",
		"TEXT ·Probe(SB),4,$0-0\n.section .text\n",
		"\"unterminated\n",
		"/* unterminated\n.section .text\n",
	} {
		err := preCPPSourceSyntax("foreign.s", []byte(source))
		var unsupported *discoveryUnsupportedCPPError
		if errors.As(err, &unsupported) {
			t.Fatalf("prior CPP/code or lexical failure acquired a first-token proof: %q: %v", source, err)
		}
	}
	for _, source := range []string{
		"// .section is only a comment\nTEXT ·Probe(SB),4,$0-0\nRET\n",
		"/* .section\n.text */\nTEXT ·Probe(SB),4,$0-0\nRET\n",
		"\n\tTEXT ·Probe(SB),4,$0-0\nRET\n",
		";\n;\tTEXT ·Probe(SB),4,$0-0\nRET\n",
		"// Empty original assembly sibling.\n",
	} {
		if err := preCPPSourceSyntax("valid.s", []byte(source)); err != nil {
			t.Fatalf("ordinary/empty source changed meaning: %v", err)
		}
	}
}

func TestPreCPPFirstTokenActualGoAssemblerAllArchitectures(t *testing.T) {
	ctx, goBinary := cppLexOracleContext(t)
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			source := ".section .text\nmov r0, #1\n"
			file := cppLexOracleSource(t, source)
			stdout, stderr, err := runDiscoveryMachineCommand(ctx, t.TempDir(),
				cppLexOracleEnvironment(arch), goBinary, "tool", "asm", "-p", "example.invalid/foreign",
				"-o", file+".o", file)
			want := fmt.Sprintf("%s:1: expected identifier, found %q", file, ".")
			if err == nil || len(stdout) != 0 || !strings.Contains(string(stderr), want) ||
				isDiscoveryGoBuildInfrastructureFailure(string(stderr)) {
				t.Fatalf("actual Go source rejection missing on %s: %v\n%s\n%s", arch, err, stdout, stderr)
			}
			err = preCPPSourceSyntax("foreign.s", []byte(source))
			var unsupported *discoveryUnsupportedCPPError
			if !errors.As(err, &unsupported) || unsupported.Line != 1 || unsupported.Directive != "." {
				t.Fatalf("actual first-token Go rejection was lost before CPP planning: %v", err)
			}
		})
	}
}

func cppLexOracleContext(t *testing.T) (context.Context, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	return ctx, binary
}

func cppLexOracleSource(t *testing.T, source string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "foreign.s")
	writeTestFile(t, file, source)
	return file
}

func cppLexOracleEnvironment(arch string) []string {
	goos := "linux"
	if arch == "wasm" {
		goos = "js"
	}
	return replaceEnv(os.Environ(), map[string]string{
		"GOOS": goos, "GOARCH": arch, "CGO_ENABLED": "0", "GOTOOLCHAIN": "local",
	})
}
