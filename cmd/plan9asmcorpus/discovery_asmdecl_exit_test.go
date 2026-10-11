package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclMetadataRequiresObservedExitOne(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/exitproof\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package exitproof\nfunc Value(x bool)\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Value(SB),$0-0\nRET\n")
	env := discoveryAsmDeclLocalFixtureEnvironment(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, observed := runCapturedCommandOutput(ctx, dir, env, "go", "vet", "-asmdecl", "./...")
	var original *discoveryCapturedCommandError
	if !errors.As(observed, &original) {
		t.Fatalf("original Go vet did not produce the intended metadata warning: %v", observed)
	}
	exitOne, ok := original.cause.(*exec.ExitError)
	if !ok || exitOne.ExitCode() != 1 || !strings.Contains(original.output, "wrong argument size 0") {
		t.Fatalf("original Go vet did not establish an actual exit 1: %v", observed)
	}

	_, unknown := runCapturedCommandOutput(ctx, dir, env, "go", "env", "-plan9asm-unknown-flag")
	var unknownFailure *discoveryCapturedCommandError
	if !errors.As(unknown, &unknownFailure) {
		t.Fatalf("Go invalid-flag fixture did not fail: %v", unknown)
	}
	exitTwo, ok := unknownFailure.cause.(*exec.ExitError)
	if !ok || exitTwo.ExitCode() != 2 {
		t.Fatalf("Go invalid-flag fixture did not establish actual exit 2: %v", unknown)
	}

	for _, test := range []struct {
		name  string
		cause error
		pass  bool
		wrap  func(error) error
	}{
		{name: "observed exit one", cause: exitOne, pass: true},
		{name: "observed exit two", cause: exitTwo},
		{name: "exit text without wait status", cause: errors.New("exit status 1")},
		{name: "missing wait status"},
		{name: "exit one plus unknown failure", cause: errors.Join(exitOne, errors.New("unknown capture failure"))},
		{name: "wrapped unexplained exit", cause: fmt.Errorf("unknown wrapper: %w", exitOne)},
		{
			name: "capture plus outer unknown failure", cause: exitOne,
			wrap: func(err error) error { return errors.Join(err, errors.New("outer unknown capture failure")) },
		},
		{
			name: "capture with outer unknown wrapper", cause: exitOne,
			wrap: func(err error) error { return fmt.Errorf("outer unknown wrapper: %w", err) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Keep the actual metadata bytes and selected source identical.
			// A different status must not borrow the original successful filter.
			failure := *original
			failure.cause = test.cause
			var input error = &failure
			if test.wrap != nil {
				input = test.wrap(input)
			}
			err := filterDiscoveryAsmDeclTextMetadata(ctx, dir, env, nil, []string{"./..."}, "", input)
			if test.pass {
				if err != nil {
					t.Fatalf("actual exit-one metadata warning was not filtered: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, errDiscoveryAsmDeclSourceProof) || !errors.Is(err, &failure) {
				t.Fatalf("unobserved/unexplained exit became success or lost its cause: %v", err)
			}
			if !isDiscoveryInfrastructureFailure(err) || !strings.Contains(discoveryCommandDiagnostic(err), original.output) {
				t.Fatalf("unexplained status lost its complete retryable failure: %v", err)
			}
		})
	}
}

func discoveryAsmDeclObservedExitOne(t *testing.T) *exec.ExitError {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/vetstatus\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package vetstatus\nfunc Value(x bool)\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Value(SB),$0-0\nRET\n")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := runCapturedCommandOutput(ctx, dir, discoveryAsmDeclLocalFixtureEnvironment(t), "go", "vet", "-asmdecl", "./...")
	var failure *discoveryCapturedCommandError
	if !errors.As(err, &failure) {
		t.Fatalf("actual Go vet metadata fixture did not fail: %v", err)
	}
	exit, ok := failure.cause.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(failure.output, "wrong argument size 0") {
		t.Fatalf("actual Go vet metadata fixture did not establish exit 1: %v", err)
	}
	return exit
}

func TestRunDiscoveryAsmDeclRequiresSuccessfulTestlessRetry(t *testing.T) {
	for _, test := range []struct {
		name              string
		invalidProduction bool
		hasInvalidTest    bool
	}{
		{"invalid production without tests", true, false},
		{"invalid production with obsolete test", true, true},
		{"only obsolete test", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/retryproof\n\ngo 1.20\n")
			source := "package retryproof\nfunc Value()\n"
			if test.invalidProduction {
				source += "var broken = missingProductionIdentifier\n"
			}
			writeTestFile(t, filepath.Join(dir, "decl.go"), source)
			writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·Value(SB),$0-0\nRET\n")
			if test.hasInvalidTest {
				writeTestFile(t, filepath.Join(dir, "decl_test.go"),
					"package retryproof\nvar obsoleteTest = missingTestIdentifier\n")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			err := runDiscoveryAsmDecl(ctx, dir, discoveryAsmDeclLocalFixtureEnvironment(t),
				"linux/amd64", nil, []string{"./..."})
			if test.invalidProduction {
				if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), "missingProductionIdentifier") {
					t.Fatalf("failed production analysis became an assembly check pass: %v", err)
				}
			} else if err != nil {
				t.Fatalf("successful actual testless analysis did not clear unrelated obsolete tests: %v", err)
			}
		})
	}
}
