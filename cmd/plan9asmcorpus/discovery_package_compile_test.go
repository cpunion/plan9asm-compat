package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryGoPackageCompileDoesNotRequireMainOrExecuteInit(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			writeDiscoveryPackageCompileFixture(t, dir, "go.mod", "module example.invalid/compile-only\n\ngo 1.20\n")
			// The unrelated root and test source must not enter the exact
			// production-package check. A compiled init must never execute.
			writeDiscoveryPackageCompileFixture(t, dir, "bad.go", "package bad\nvar Invalid = undefinedRoot\n")
			writeDiscoveryPackageCompileFixture(t, dir, "asmcmd/main.go", "//go:build corpus_feature\n\npackage main\nfunc F()\nfunc init() { panic(\"compile checks must not execute init\") }\n")
			writeDiscoveryPackageCompileFixture(t, dir, "asmcmd/invalid_test.go", "package main\nvar InvalidTest = undefinedTest\n")
			writeDiscoveryPackageCompileFixture(t, dir, "asmcmd/f.s", "TEXT ·F(SB),4,$0-0\nRET\n")
			env := replaceEnv(os.Environ(), map[string]string{
				"GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOPROXY": "off",
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			packageDir := filepath.Join(dir, "asmcmd")
			if err := runDiscoveryGoBuild(ctx, packageDir, env, target, []string{"corpus_feature"}, "."); err != nil {
				t.Fatalf("an exact assembly package needs compilation, not a main entry point: %v", err)
			}
			for _, name := range []string{"asmcmd", "asmcmd.exe", "compile-only", "compile-only.exe"} {
				if _, err := os.Stat(filepath.Join(packageDir, name)); !os.IsNotExist(err) {
					t.Errorf("compile-only check unexpectedly published executable %s: %v", name, err)
				}
			}
		})
	}
}

func TestDiscoveryGoPackageCompileStillRejectsSourceAndAssemblyErrors(t *testing.T) {
	for _, test := range []struct {
		name, goSource, asm, diagnostic string
	}{
		{"go_source", "package main\nvar X = missingGoIdentifier\nfunc F()\n", "TEXT ·F(SB),4,$0-0\nRET\n", "undefined: missingGoIdentifier"},
		{"assembly_source", "package main\nfunc F()\n", "TEXT ·F(SB),4,$0-0\nNOT_A_REAL_OPCODE\nRET\n", "NOT_A_REAL_OPCODE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDiscoveryPackageCompileFixture(t, dir, "go.mod", "module example.invalid/rejected\n\ngo 1.20\n")
			writeDiscoveryPackageCompileFixture(t, dir, "main.go", test.goSource)
			writeDiscoveryPackageCompileFixture(t, dir, "f_amd64.s", test.asm)
			env := replaceEnv(os.Environ(), map[string]string{
				"GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOPROXY": "off",
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			err := runDiscoveryGoBuild(ctx, dir, env, "linux/amd64", nil, ".")
			if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), test.diagnostic) {
				t.Fatalf("compilation lost the concrete source diagnostic: %v", err)
			}
		})
	}
}

func writeDiscoveryPackageCompileFixture(t *testing.T, dir, name, source string) {
	t.Helper()
	file := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
}
