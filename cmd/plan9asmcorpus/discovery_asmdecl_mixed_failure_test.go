package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclOwnABIMixedFailuresRemainFailure(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/ownmixed\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), `package ownmixed
func Bad() uint64
func Unwritten() uint64
`)
	writeTestFile(t, filepath.Join(dir, "bad_amd64.s"), `TEXT ·Bad(SB),4,$0-8
MOVQ $1, ret+8(FP)
RET
`)
	writeTestFile(t, filepath.Join(dir, "unwritten_amd64.s"), `TEXT ·Unwritten(SB),4,$0-8
RET
`)
	files := []string{"bad_amd64.s", "unwritten_amd64.s"}
	mixed := discoveryAsmDeclMixedActualVet(t, dir, "./...")
	discoveryAsmDeclMixedRequireDiagnostics(t, mixed, "invalid offset ret+8(FP)", "RET without writing")

	t.Run("actual own ABI and other own unwritten result", func(t *testing.T) {
		rejected, err := classifyDiscoveryAsmDeclFailure(dir, files, files, mixed)
		if err == nil {
			t.Fatalf("actual own ABI warning hid another file's unwritten result; rejected=%v: %s", rejected, mixed.output)
		}
		if !strings.Contains(discoveryCommandDiagnostic(err), "RET without writing") {
			t.Fatalf("mixed failure lost the original RET diagnostic: %v", err)
		}
	})

	// This change is a legitimate, fully written result, not a change to the
	// invalid-offset warning. Stock Go must now report only the ABI mismatch.
	writeTestFile(t, filepath.Join(dir, "unwritten_amd64.s"), `TEXT ·Unwritten(SB),4,$0-8
MOVQ $2, ret+0(FP)
RET
`)
	abiOnly := discoveryAsmDeclMixedActualVet(t, dir, "./...")
	discoveryAsmDeclMixedRequireDiagnostics(t, abiOnly, "invalid offset ret+8(FP)")
	if strings.Contains(abiOnly.output, "RET without writing") {
		t.Fatalf("ABI-only control retained an unwritten result: %s", abiOnly.output)
	}
	t.Run("actual own ABI only", func(t *testing.T) {
		rejected, err := classifyDiscoveryAsmDeclFailure(dir, files, files, abiOnly)
		if err != nil || !reflect.DeepEqual(rejected, []string{"bad_amd64.s"}) {
			t.Fatalf("concrete ABI-only control was not attributed exactly: rejected=%v err=%v", rejected, err)
		}
	})

	t.Run("unit output tripwire own ABI and unknown diagnostic", func(t *testing.T) {
		// The unknown line is deliberately mutated output, not stock-Go or an
		// external-library certificate. Only the exit wait status is observed.
		failure := *abiOnly
		failure.cause = discoveryAsmDeclObservedExitOne(t)
		failure.output += "unwritten_amd64.s:2:1: [amd64] Unwritten: unknown assembly diagnostic\n"
		rejected, err := classifyDiscoveryAsmDeclFailure(dir, files, files, &failure)
		if err == nil {
			t.Fatalf("unit tripwire unknown diagnostic was discarded; rejected=%v: %s", rejected, failure.output)
		}
	})
}

func TestDiscoveryAsmDeclForeignABIMixedFailuresRemainFailure(t *testing.T) {
	dir := t.TempDir()
	for _, pkg := range []string{"dep", "own"} {
		if err := os.MkdirAll(filepath.Join(dir, pkg), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/foreignmixed\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "dep", "decl.go"), "package dep\nfunc Bad() uint64\n")
	writeTestFile(t, filepath.Join(dir, "dep", "bad_amd64.s"), `TEXT ·Bad(SB),4,$0-8
MOVQ $1, ret+8(FP)
RET
`)
	writeTestFile(t, filepath.Join(dir, "own", "decl.go"), "package own\nfunc Unwritten() uint64\n")
	writeTestFile(t, filepath.Join(dir, "own", "decl_test.go"), `package own
import _ "example.invalid/foreignmixed/dep"
`)
	writeTestFile(t, filepath.Join(dir, "own", "unwritten_amd64.s"), `TEXT ·Unwritten(SB),4,$0-8
RET
`)
	candidate := []string{"dep/bad_amd64.s", "own/unwritten_amd64.s"}
	own := []string{"own/unwritten_amd64.s"}
	// This is a real batched vet of the two selected packages, not a claim
	// that vet ./own reports every dependency. The dependency ABI diagnostic
	// is foreign relative to the own-package scope used by the closure below.
	mixed := discoveryAsmDeclMixedActualVet(t, dir, "./...")
	discoveryAsmDeclMixedRequireDiagnostics(t, mixed,
		"dep/bad_amd64.s", "invalid offset ret+8(FP)", "own/unwritten_amd64.s", "RET without writing")
	t.Run("actual foreign ABI and own unwritten result", func(t *testing.T) {
		if discoveryAsmDeclOnlyForeignCandidateABI(dir, candidate, own, mixed) {
			t.Fatalf("actual own RET failure was hidden by the dependency ABI warning: %s", mixed.output)
		}
	})

	writeTestFile(t, filepath.Join(dir, "own", "unwritten_amd64.s"), `TEXT ·Unwritten(SB),4,$0-8
MOVQ $2, ret+0(FP)
RET
`)
	foreignOnly := discoveryAsmDeclMixedActualVet(t, dir, "./...")
	discoveryAsmDeclMixedRequireDiagnostics(t, foreignOnly, "dep/bad_amd64.s", "invalid offset ret+8(FP)")
	if strings.Contains(foreignOnly.output, "RET without writing") {
		t.Fatalf("foreign-only control retained an unwritten result: %s", foreignOnly.output)
	}
	t.Run("actual foreign ABI only", func(t *testing.T) {
		if !discoveryAsmDeclOnlyForeignCandidateABI(dir, candidate, own, foreignOnly) {
			t.Fatalf("actual dependency-only mismatch was attributed to the valid own package: %s", foreignOnly.output)
		}
	})

	t.Run("unit output tripwire foreign ABI and own unknown diagnostic", func(t *testing.T) {
		// Only this unknown diagnostic is synthetic; this is a unit closure
		// tripwire, not evidence that stock Go emitted the mutated line.
		failure := *foreignOnly
		failure.cause = discoveryAsmDeclObservedExitOne(t)
		failure.output += "own/unwritten_amd64.s:2:1: [amd64] Unwritten: unknown assembly diagnostic\n"
		if discoveryAsmDeclOnlyForeignCandidateABI(dir, candidate, own, &failure) {
			t.Fatalf("unit tripwire own unknown diagnostic was hidden by a foreign ABI warning: %s", failure.output)
		}
	})
}

func TestDiscoveryAsmDeclMixedFailureFullyWrittenControl(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/writtencontrol\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package writtencontrol\nfunc Value() uint64\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), `TEXT ·Value(SB),4,$0-8
MOVQ $3, ret+0(FP)
RET
`)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := runCapturedCommandOutput(ctx, dir, discoveryAsmDeclLocalFixtureEnvironment(t), "go", "vet", "-asmdecl", "./...")
	if err != nil {
		t.Fatalf("actual fully written ABI control failed stock Go vet: %v", err)
	}
	if rejected, err := classifyDiscoveryAsmDeclFailure(dir, []string{"decl_amd64.s"}, []string{"decl_amd64.s"}, nil); err != nil || len(rejected) != 0 {
		t.Fatalf("legitimate nil diagnostic became a rejection: rejected=%v err=%v", rejected, err)
	}
	if discoveryAsmDeclOnlyForeignCandidateABI(dir, []string{"decl_amd64.s"}, []string{"decl_amd64.s"}, nil) {
		t.Fatal("legitimate success was mislabeled a foreign ABI failure")
	}
}

func discoveryAsmDeclMixedActualVet(t *testing.T, dir, pattern string) *discoveryCapturedCommandError {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := runCapturedCommandOutput(ctx, dir, discoveryAsmDeclLocalFixtureEnvironment(t), "go", "vet", "-asmdecl", pattern)
	var failure *discoveryCapturedCommandError
	if !errors.As(err, &failure) {
		t.Fatalf("stock Go vet did not capture the intended assembly failure: %v", err)
	}
	exit, ok := failure.cause.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 {
		t.Fatalf("stock Go vet did not provide the required actual exit-one wait status: %v", err)
	}
	t.Logf("actual stock-Go argv: go vet -asmdecl %s; exit=%d; complete diagnostic:\n%s", pattern, exit.ExitCode(), failure.output)
	return failure
}

func discoveryAsmDeclMixedRequireDiagnostics(t *testing.T, failure *discoveryCapturedCommandError, needles ...string) {
	t.Helper()
	for _, needle := range needles {
		if !strings.Contains(failure.output, needle) {
			t.Fatalf("actual assembly fixture lacks %q: %s", needle, failure.output)
		}
	}
}
