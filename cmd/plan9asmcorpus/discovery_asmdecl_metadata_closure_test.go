package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclMetadataCannotDiscardUnobservedScope(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/metadataclosure\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package metadataclosure\nfunc Value(x bool)\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Value(SB),$0-0\nRET\n")
	env := discoveryAsmDeclLocalFixtureEnvironment(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := runCapturedCommandOutput(ctx, dir, env, "go", "vet", "-asmdecl", "./...")
	observed, actual := discoveryAsmDeclObservedFailure(err)
	if !actual || !strings.Contains(observed.output, "wrong argument size 0") {
		t.Fatalf("stock Go did not emit the intended plain exit-one metadata diagnostic: %v", err)
	}

	for _, test := range []struct {
		name string
		edit func(*discoveryCapturedCommandError)
	}{
		{"unknown trailing heading", func(failure *discoveryCapturedCommandError) {
			failure.output += "# unknown analysis failure\n"
		}},
		{"unknown trailing test heading", func(failure *discoveryCapturedCommandError) {
			failure.output += "# example.invalid/metadataclosure [test] ignored failure\n"
		}},
		{"unknown architecture", func(failure *discoveryCapturedCommandError) {
			failure.output = strings.ReplaceAll(failure.output, "[amd64]", "[mips]")
		}},
		{"filename architecture mismatch", func(failure *discoveryCapturedCommandError) {
			failure.output = strings.ReplaceAll(failure.output, "[amd64]", "[arm64]")
		}},
		{"zero diagnostic column", func(failure *discoveryCapturedCommandError) {
			failure.output = strings.ReplaceAll(failure.output, ".s:1:1: [amd64]", ".s:1:0: [amd64]")
		}},
		{"overflow diagnostic column", func(failure *discoveryCapturedCommandError) {
			failure.output = strings.ReplaceAll(failure.output, ".s:1:1: [amd64]", ".s:1:9223372036854775808: [amd64]")
		}},
		{"overflow expected argument size", func(failure *discoveryCapturedCommandError) {
			failure.output = strings.ReplaceAll(failure.output, "expected $...-1", "expected $...-9223372036854775808")
		}},
		{"unrelated command directory", func(failure *discoveryCapturedCommandError) {
			failure.directory = t.TempDir()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Only the original bytes above are actual Go diagnostics. Each
			// clone below is an explicit corrupted-output/identity unit fixture;
			// sharing its real exit status must not borrow successful analysis.
			failure := *observed
			test.edit(&failure)
			if failure.output == observed.output && failure.directory == observed.directory {
				t.Fatal("tripwire did not mutate the intended output or command scope")
			}
			filtered := filterDiscoveryAsmDeclTextMetadata(ctx, dir, env, nil, []string{"./..."}, "", &failure)
			if filtered == nil || !strings.Contains(discoveryCommandDiagnostic(filtered), failure.output) {
				t.Fatalf("unobserved scope was discarded or lost its complete diagnostic: %v", filtered)
			}
		})
	}
}

func TestDiscoveryAsmDeclMetadataAcceptsOnlyOriginalCompletedScope(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/metadatapositive\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package metadatapositive\nfunc Value(x bool)\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Value(SB),$0-0\nRET\n")
	env := discoveryAsmDeclLocalFixtureEnvironment(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := runCapturedCommandOutput(ctx, dir, env, "go", "vet", "-asmdecl", "./...")
	if _, actual := discoveryAsmDeclObservedFailure(err); !actual {
		t.Fatalf("stock Go did not complete the metadata-only fixture: %v", err)
	}
	if filtered := filterDiscoveryAsmDeclTextMetadata(ctx, dir, env, nil, []string{"./..."}, "", err); filtered != nil {
		t.Fatalf("original completed metadata-only scope remained rejected: %v", filtered)
	}
	if errors.Is(err, errDiscoveryAsmDeclSourceProof) {
		t.Fatal("original completed invocation was mislabeled as source-proof infrastructure failure")
	}
}
