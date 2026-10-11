package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclRelativeDiagnosticsBindCommandDirectory(t *testing.T) {
	exitOne := discoveryAsmDeclObservedExitOne(t)
	for _, test := range []struct {
		name, reported, heading string
		removeMetadata          bool
	}{
		{"selected subdirectory", "selected/decl_amd64.s", "example.invalid/relative/selected", true},
		{"selected dot prefix", "./selected/decl_amd64.s", "example.invalid/relative/selected", true},
		{"foreign same basename", "foreign/decl_amd64.s", "example.invalid/relative/selected", false},
		{"foreign unqualified basename", "decl_amd64.s", "example.invalid/relative/selected", false},
		{"foreign heading", "selected/decl_amd64.s", "example.invalid/foreign", false},
		{"nonselected spelling", "selected/not_selected.s", "example.invalid/relative/selected", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"selected", "foreign"} {
				if err := os.MkdirAll(filepath.Join(root, name), 0755); err != nil {
					t.Fatal(err)
				}
			}
			writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/relative\n\ngo 1.20\n")
			writeTestFile(t, filepath.Join(root, "selected", "decl.go"), "package selected\nfunc Value() bool\n")
			writeTestFile(t, filepath.Join(root, "selected", "decl_amd64.s"), "TEXT ·Value(SB),$0\nRET\n")
			writeTestFile(t, filepath.Join(root, "foreign", "decl_amd64.s"), "TEXT ·Value(SB),$0\nRET\n")
			writeTestFile(t, filepath.Join(root, "decl_amd64.s"), "TEXT ·Value(SB),$0\nRET\n")

			metadata := test.reported + ":1:1: [amd64] Value: wrong argument size 0; expected $...-1"
			realFailure := "selected/decl_amd64.s:2:1: [amd64] Value: invalid offset ret+4(FP); expected ret+0(FP)"
			original := &discoveryCapturedCommandError{
				directory: root,
				command:   "go vet -asmdecl", cause: exitOne,
				output: "# " + test.heading + "\n" + metadata + "\n" + realFailure + "\n",
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			err := filterDiscoveryAsmDeclTextMetadata(
				ctx, root, discoveryAsmDeclLocalFixtureEnvironment(t), nil,
				[]string{"./selected"}, "", original,
			)
			if err == nil {
				t.Fatal("relative metadata filtering hid the actual ABI failure")
			}
			diagnostic := discoveryCommandDiagnostic(err)
			if !strings.Contains(diagnostic, realFailure) {
				t.Fatalf("actual ABI diagnostic changed: %v", err)
			}
			if removed := !strings.Contains(diagnostic, metadata); removed != test.removeMetadata {
				t.Fatalf("command-directory binding removed=%v, want %v: %v", removed, test.removeMetadata, err)
			}
		})
	}
}

func TestDiscoveryAsmDeclRelativeStagedModuleBinding(t *testing.T) {
	exitOne := discoveryAsmDeclObservedExitOne(t)
	root := t.TempDir()
	working := filepath.Join(root, "work")
	staged := filepath.Join(root, "staged")
	for _, dir := range []string{working, staged} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(working, "go.mod"), "module example.invalid/driver\n\ngo 1.20\n\nrequire example.invalid/staged v0.0.0\nreplace example.invalid/staged => ../staged\n")
	writeTestFile(t, filepath.Join(staged, "go.mod"), "module example.invalid/staged\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(staged, "decl.go"), "package staged\nfunc Value() bool\n")
	writeTestFile(t, filepath.Join(staged, "decl_amd64.s"), "TEXT ·Value(SB),$0\nRET\n")
	metadata := "../staged/decl_amd64.s:1:1: [amd64] Value: wrong argument size 0; expected $...-1\n"
	original := &discoveryCapturedCommandError{
		directory: working,
		command:   "go vet -asmdecl", cause: exitOne,
		output: "# example.invalid/staged\n" + metadata,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(working, linked); err != nil {
		t.Fatal(err)
	}
	for _, commandDir := range []string{working, linked} {
		t.Run(filepath.Base(commandDir), func(t *testing.T) {
			err := filterDiscoveryAsmDeclTextMetadata(
				ctx, commandDir, discoveryAsmDeclLocalFixtureEnvironment(t), nil,
				[]string{"example.invalid/staged"}, "", original,
			)
			if err != nil {
				t.Fatalf("exact selected staged source failed its actual command-directory binding: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclRelativePaddedArgsRetainsOtherDiagnostics(t *testing.T) {
	exitOne := discoveryAsmDeclObservedExitOne(t)
	root := t.TempDir()
	dir := filepath.Join(root, "selected")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/padded\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "sqrt.go"), "package selected\nfunc Sqrt(x float32) (r float32)\n")
	writeTestFile(t, filepath.Join(dir, "sqrt_amd64.s"), "TEXT ·Sqrt(SB),$0-16\nRET\n")
	metadata := "selected/sqrt_amd64.s:1:1: [amd64] Sqrt: wrong argument size 16; expected $...-12"
	realFailure := "selected/sqrt_amd64.s:2:1: [amd64] Sqrt: invalid offset r+12(FP); expected r+8(FP)"
	original := &discoveryCapturedCommandError{
		directory: root,
		command:   "go vet -asmdecl", cause: exitOne,
		output: "# example.invalid/padded/selected\n" + metadata + "\n" + realFailure + "\n",
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err := filterDiscoveryAsmDeclTextMetadata(
		ctx, root, discoveryAsmDeclLocalFixtureEnvironment(t), nil,
		[]string{"./selected"}, "", original,
	)
	if err == nil {
		t.Fatal("relative padded-args filtering hid the actual ABI failure")
	}
	diagnostic := discoveryCommandDiagnostic(err)
	if strings.Contains(diagnostic, metadata) || !strings.Contains(diagnostic, realFailure) {
		t.Fatalf("relative padded-args filtering changed the wrong diagnostic: %v", err)
	}
}

func TestDiscoveryAsmDeclRelativeLogicalWorkingDirectory(t *testing.T) {
	exitOne := discoveryAsmDeclObservedExitOne(t)
	root := t.TempDir()
	working := filepath.Join(root, "physical")
	selected := filepath.Join(working, "selected")
	if err := os.MkdirAll(selected, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(working, "go.mod"), "module example.invalid/logical\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(selected, "decl.go"), "package selected\nfunc Value() bool\n")
	writeTestFile(t, filepath.Join(selected, "decl_amd64.s"), "TEXT ·Value(SB),$0\nRET\n")
	linked := filepath.Join(root, "logical")
	if err := os.Symlink(working, linked); err != nil {
		t.Fatal(err)
	}
	env := replaceEnv(discoveryAsmDeclLocalFixtureEnvironment(t), map[string]string{"PWD": linked})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, test := range []struct{ name, reported string }{
		{"relative", "selected/decl_amd64.s"},
		{"absolute logical", filepath.Join(linked, "selected", "decl_amd64.s")},
		{"absolute physical", filepath.Join(selected, "decl_amd64.s")},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := &discoveryCapturedCommandError{
				directory: linked,
				command:   "go vet -asmdecl", cause: exitOne,
				output: "# example.invalid/logical/selected\n" + test.reported +
					":1:1: [amd64] Value: wrong argument size 0; expected $...-1\n",
			}
			err := filterDiscoveryAsmDeclTextMetadata(ctx, linked, env, nil, []string{"./selected"}, "", original)
			if err != nil {
				t.Fatalf("actual logical Go package path did not bind its physical command directory: %v", err)
			}
		})
	}
}

func discoveryAsmDeclLocalFixtureEnvironment(t *testing.T) []string {
	t.Helper()
	return replaceEnv(os.Environ(), map[string]string{
		"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0",
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
		"GOFLAGS": "-mod=mod", "GOPROXY": "off",
	})
}
