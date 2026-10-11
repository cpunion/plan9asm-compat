package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"
)

// These are deliberately mutated-output unit tripwires, not certificates that
// stock Go emitted their diagnostics. The wait statuses alone come from real
// stock-Go commands; source/target attribution must not be inferred from them.
func TestDiscoveryAsmDeclWarningClosureGrammarTripwires(t *testing.T) {
	exitOne := discoveryAsmDeclObservedExitOne(t)
	for _, test := range []struct {
		name, diagnostic string
		known, abi       bool
	}{
		{"missing declaration", "function Value missing Go declaration", true, false},
		{"resolved named alias", "unknown variable x; offset 0 is a+0(FP)", true, false},
		{"resolved unnamed alias", "use of unnamed argument 0(FP); offset 0 is a+0(FP)", true, false},
		{"equal scalar width", "invalid MOVQ of a+0(FP); float64 is 8-byte value", true, false},
		{"equal complete aggregate width", "invalid MOVOU of a+0(FP); [2]uint64 is 16-byte value containing a_0+0(FP) and a_1+8(FP)", true, false},
		{"equal broadcast source width", "invalid VPBROADCASTB of a+0(FP); [1]uint8 is 1-byte value containing a_0+0(FP)", true, false},
		{"unequal scalar width", "invalid MOVQ of a+0(FP); [2]uint64 is 16-byte value containing a_0+0(FP) and a_1+8(FP)", false, true},
		{"unequal broadcast source width", "invalid VPBROADCASTB of a+0(FP); uint64 is 8-byte value", false, true},
		{"concrete argument size", "wrong argument size 8; expected $...-16", false, true},
		{"matching argument size is not mismatch", "wrong argument size 8; expected $...-8", false, false},
		{"concrete invalid offset", "invalid offset ret+8(FP); expected ret+0(FP)", false, true},
		{"complete aggregate offsets", "invalid offset a+8(FP); expected a+0(FP), a_0+0(FP), or a_1+8(FP)", false, true},
		{"unwritten result", "RET without writing to 8-byte ret+0(FP)", false, false},
		{"unknown warning", "unknown assembly diagnostic", false, false},
		{"declaration symbol mismatch", "function Other missing Go declaration", false, false},
		{"unresolved named alias", "unknown variable x", false, false},
		{"alias offset mismatch", "unknown variable x; offset 1 is a+0(FP)", false, false},
		{"alias offset overflow", "unknown variable x; offset 9223372036854775808 is a+9223372036854775808(FP)", false, false},
		{"width unknown tail", "invalid MOVQ of a+0(FP); float64 is 8-byte value; unknown failure", false, false},
		{"width incomplete containing", "invalid MOVOU of a+0(FP); [2]uint64 is 16-byte value containing", false, false},
		{"offset unknown tail", "invalid offset ret+8(FP); expected ret+0(FP); unknown failure", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			line := "valid_amd64.s:2:1: [amd64] Value: " + test.diagnostic
			if got := discoveryAsmDeclKnownNonABIWarning(line); got != test.known {
				t.Fatalf("known-warning grammar=%v, want %v: %s", got, test.known, line)
			}
			if got := discoveryAsmDeclConcreteABIWarning(line); got != test.abi {
				t.Fatalf("concrete-ABI grammar=%v, want %v: %s", got, test.abi, line)
			}
			failure := &discoveryCapturedCommandError{command: "go vet -asmdecl", cause: exitOne, output: line + "\n"}
			if got := discoveryAsmDeclOnlyKnownNonABIWarnings(failure); got != test.known {
				t.Fatalf("whole known-warning closure=%v, want %v: %s", got, test.known, line)
			}
		})
	}
}

func TestDiscoveryAsmDeclWarningClosureAttributionTripwires(t *testing.T) {
	exitOne := discoveryAsmDeclObservedExitOne(t)
	const abi = "valid_amd64.s:2:1: [amd64] Value: invalid offset ret+8(FP); expected ret+0(FP)\n"
	const known = "valid_amd64.s:1:1: [amd64] Value: function Value missing Go declaration\n"
	for _, test := range []struct {
		name, extra string
		complete    bool
	}{
		{"ABI only", "", true},
		{"same candidate known warning", known, true},
		{"outside candidate known warning", "outside/unregistered_amd64.s:1:1: [amd64] Other: function Other missing Go declaration\n", false},
		{"outside candidate resolved alias", "outside/unregistered_amd64.s:2:1: [amd64] Other: unknown variable x; offset 0 is a+0(FP)\n", false},
		{"outside candidate equal width", "outside/unregistered_amd64.s:2:1: [amd64] Other: invalid MOVQ of a+0(FP); float64 is 8-byte value\n", false},
		{"unknown heading", "# unknown analysis failure\n", false},
		{"unwritten result", "valid_amd64.s:3:1: [amd64] Value: RET without writing to 8-byte ret+0(FP)\n", false},
		{"unknown diagnostic", "valid_amd64.s:3:1: [amd64] Value: unknown diagnostic\n", false},
		{"zero line", "valid_amd64.s:0:1: [amd64] Value: function Value missing Go declaration\n", false},
		{"zero column", "valid_amd64.s:1:0: [amd64] Value: function Value missing Go declaration\n", false},
		{"line overflow", "valid_amd64.s:9223372036854775808:1: [amd64] Value: function Value missing Go declaration\n", false},
		{"column overflow", "valid_amd64.s:1:9223372036854775808: [amd64] Value: function Value missing Go declaration\n", false},
		{"unknown architecture", "valid_amd64.s:1:1: [mips] Value: function Value missing Go declaration\n", false},
		{"file architecture mismatch", "valid_amd64.s:1:1: [arm64] Value: function Value missing Go declaration\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := &discoveryCapturedCommandError{command: "go vet -asmdecl", cause: exitOne, output: abi + test.extra}
			lines, complete := discoveryAsmDeclCompleteABIDiagnostics([]string{"valid_amd64.s"}, failure)
			if complete != test.complete {
				t.Fatalf("whole candidate ABI closure=%v, want %v; lines=%v; unit output:\n%s", complete, test.complete, lines, failure.output)
			}
		})
	}

	t.Run("unknown heading cannot hide beside known warning", func(t *testing.T) {
		failure := &discoveryCapturedCommandError{command: "go vet -asmdecl", cause: exitOne, output: "# unknown analysis failure\n" + known}
		if discoveryAsmDeclOnlyKnownNonABIWarnings(failure) {
			t.Fatalf("unit unknown heading was silently discarded beside a known warning: %s", failure.output)
		}
	})
}

func TestDiscoveryAsmDeclWarningClosureObservedStatusTripwires(t *testing.T) {
	exitOne := discoveryAsmDeclObservedExitOne(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := runCapturedCommandOutput(ctx, t.TempDir(), discoveryAsmDeclLocalFixtureEnvironment(t), "go", "env", "-plan9asm-invalid-flag")
	var captured *discoveryCapturedCommandError
	if !errors.As(err, &captured) {
		t.Fatalf("stock Go invalid flag did not provide a captured failure: %v", err)
	}
	exitTwo, ok := captured.cause.(*exec.ExitError)
	if !ok || exitTwo.ExitCode() != 2 {
		t.Fatalf("stock Go invalid flag did not establish actual exit two: %v", err)
	}
	const known = "valid_amd64.s:1:1: [amd64] Value: function Value missing Go declaration\n"
	const abi = "valid_amd64.s:2:1: [amd64] Value: invalid offset ret+8(FP); expected ret+0(FP)\n"
	for _, test := range []struct {
		name  string
		cause error
		wrap  func(error) error
		valid bool
	}{
		{name: "actual plain exit one", cause: exitOne, valid: true},
		{name: "actual exit two", cause: exitTwo},
		{name: "missing wait status"},
		{name: "joined inner cause", cause: errors.Join(exitOne, errors.New("unknown inner failure"))},
		{name: "wrapped inner cause", cause: fmt.Errorf("unknown inner wrapper: %w", exitOne)},
		{name: "joined outer failure", cause: exitOne, wrap: func(err error) error { return errors.Join(err, errors.New("unknown outer failure")) }},
		{name: "wrapped outer failure", cause: exitOne, wrap: func(err error) error { return fmt.Errorf("unknown outer wrapper: %w", err) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, output := range []string{known, abi} {
				var failure error = &discoveryCapturedCommandError{command: "go vet -asmdecl", cause: test.cause, output: output}
				if test.wrap != nil {
					failure = test.wrap(failure)
				}
				got := discoveryAsmDeclOnlyKnownNonABIWarnings(failure)
				if output == abi {
					_, got = discoveryAsmDeclCompleteABIDiagnostics([]string{"valid_amd64.s"}, failure)
				}
				if got != test.valid {
					t.Fatalf("observed-status closure=%v, want %v for unit output %q: %v", got, test.valid, output, failure)
				}
			}
		})
	}
	for _, output := range []string{"", "# example.invalid/headeronly\n"} {
		failure := &discoveryCapturedCommandError{command: "go vet -asmdecl", cause: exitOne, output: output}
		if discoveryAsmDeclOnlyKnownNonABIWarnings(failure) {
			t.Fatalf("empty/header-only failed analysis became known-warning success: %q", output)
		}
		if _, complete := discoveryAsmDeclCompleteABIDiagnostics([]string{"valid_amd64.s"}, failure); complete {
			t.Fatalf("empty/header-only failed analysis became complete ABI analysis: %q", output)
		}
	}
}
