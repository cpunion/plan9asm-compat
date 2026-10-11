//go:build go1.27

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Go's issue47317 is a builddir (compile/link only) fixture whose bare RET
// does not initialize its [2]int result. The independent fixture below keeps
// that obligation a failure, not an instruction gap, source N/A or skip.
func TestDiscoveryAsmDeclUnprovedResultDiagnosticActualGo(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/unproved-results\n\ngo 1.20\n")
	declarations := "package results\n"
	var files []string
	for _, fixture := range []struct{ name, declaration, frame, body string }{
		{"Byte", "() uint8", "1", "RET"},
		{"Word", "() uint16", "2", "RET"},
		{"Long", "() uint32", "4", "RET"},
		{"Quad", "() uint64", "8", "RET"},
		{"Array", "(x int) [2]int", "24", "RET"},
		{"Struct", "() struct { A, B uint64 }", "16", "RET"},
		{"Branches", "(x uint64) uint64", "16", "MOVQ x+0(FP),AX\nCMPQ AX,$0\nJE other\nRET\nother:\nRET"},
		{"UnknownAlias", "() uint64", "8", "MOVQ AX,ret0+0(FP)\nRET"},
		{"PartialAlias", "() uint64", "8", "MOVL $1,ret0+0(FP)\nRET"},
		{"PointerAlias", "(p *uint64) uint64", "16", "MOVQ p+0(FP),AX\nMOVQ (AX),BX\nMOVQ BX,ret0+8(FP)\nRET"},
	} {
		declarations += "func " + fixture.name + fixture.declaration + "\n"
		filename := strings.ToLower(fixture.name) + "_amd64.s"
		files = append(files, filename)
		writeTestFile(t, filepath.Join(root, filename), "TEXT ·"+fixture.name+"(SB),4,$0-"+fixture.frame+"\n"+fixture.body+"\n")
	}
	writeTestFile(t, filepath.Join(root, "decl.go"), declarations)
	env := replaceEnv(discoveryAsmDeclDirectFixtureEnv(t, root), map[string]string{"GOFLAGS": "", "GOEXPERIMENT": ""})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	original := plan.run(ctx)
	failure, observed := discoveryAsmDeclObservedFailure(original)
	if !observed || strings.Count(failure.output, "RET without writing") != 11 {
		t.Fatalf("actual complete typed result obligations differ: %v", original)
	}
	t.Logf("ACTUAL_UNPROVED_RESULT_RECEIPT: %v", original)
	before := *failure
	rejected, got := classifyDiscoveryAsmDeclFailure(root, files, files, original)
	if got == nil || len(rejected) != 0 || !errors.Is(got, original) ||
		!strings.Contains(got.Error(), "unproved_result_initialization") || !reflect.DeepEqual(before, *failure) {
		t.Errorf("precise failure-only result reason missing or original receipt changed: %v %v", rejected, got)
	}
	if discoveryAsmDeclOnlyKnownNonABIWarnings(got) || discoveryAsmDeclOnlyForeignCandidateABI(root, files, files, got) {
		t.Fatal("result diagnostic acquired benign/foreign ABI permission")
	}

	// These are deliberately mutated diagnostic tripwires, never positive
	// source certificates. Unknown/mixed/tool/source failures retain their
	// complete identity rather than acquiring a narrower result-only reason.
	for name, change := range map[string]func(*discoveryCapturedCommandError) error{
		"unknown line": func(copy *discoveryCapturedCommandError) error { copy.output += "unknown failure\n"; return copy },
		"mixed ABI": func(copy *discoveryCapturedCommandError) error {
			copy.output += filepath.Join(root, files[0]) + ":1:1: [amd64] Byte: wrong argument size 8; expected $...-1\n"
			return copy
		},
		"canceled": func(copy *discoveryCapturedCommandError) error {
			copy.cause = context.Canceled
			return copy
		},
		"deadline": func(copy *discoveryCapturedCommandError) error {
			copy.cause = context.DeadlineExceeded
			return copy
		},
		"no Wait": func(copy *discoveryCapturedCommandError) error {
			copy.cause = fmt.Errorf("unobserved failure")
			return copy
		},
		"joined unknown": func(copy *discoveryCapturedCommandError) error {
			return errors.Join(copy, fmt.Errorf("unknown joined failure"))
		},
		"source guard": func(copy *discoveryCapturedCommandError) error {
			return errors.Join(copy, fmt.Errorf("%w: changed source", errDiscoveryAsmDeclSourceProof))
		},
		"incomplete batch": func(copy *discoveryCapturedCommandError) error {
			return combineDiscoveryAsmDeclAnalysisFailures([]error{copy}, 1, 2)
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := before
			changed := change(&copy)
			rejected, got := classifyDiscoveryAsmDeclFailure(root, files, files, changed)
			if got == nil || len(rejected) != 0 || !errors.Is(got, changed) || strings.Contains(got.Error(), "unproved_result_initialization") {
				t.Fatalf("mixed/unobserved failure gained a result-only reason: %v %v", rejected, got)
			}
		})
	}
	for _, scoped := range [][]string{files[:1], {"missing_amd64.s"}} {
		_, got := classifyDiscoveryAsmDeclFailure(root, scoped, files, original)
		if got == nil || strings.Contains(got.Error(), "unproved_result_initialization") {
			t.Fatalf("foreign package result was assigned to current source: %v", got)
		}
	}
}

func TestDiscoveryAsmDeclUnprovedResultDiagnosticActualBatch(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/result-batch\n\ngo 1.20\n")
	files := []string{"one/decl_amd64.s", "two/decl_amd64.s"}
	for _, file := range files {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(file)), 0755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(root, filepath.Dir(file), "decl.go"), "package result\nfunc Value() uint64\n")
		writeTestFile(t, filepath.Join(root, file), "TEXT ·Value(SB),4,$0-8\nRET\n")
	}
	env := replaceEnv(discoveryAsmDeclDirectFixtureEnv(t, root), map[string]string{"GOFLAGS": "", "GOEXPERIMENT": ""})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"./..."}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	original := plan.run(ctx)
	failures, observed := discoveryAsmDeclObservedFailures(original)
	if !observed || len(failures) != 2 {
		t.Fatalf("missing independently completed actual two-unit batch: %v", original)
	}
	if rejected, got := classifyDiscoveryAsmDeclFailure(root, files, files, original); len(rejected) != 0 ||
		got == nil || !errors.Is(got, original) || !strings.Contains(got.Error(), "unproved_result_initialization") {
		t.Fatalf("complete result-only batch did not retain its precise failure: %v %v", rejected, got)
	}

	// Preserve the actual exit-two tool failure, then use its Wait status as
	// a negative-only receipt mutation. Neither may borrow exit-one meaning.
	_, toolErr := runCapturedCommandOutput(ctx, root, env, plan.GoBinary, "env", "-plan9asm-invalid-flag")
	var toolFailure *discoveryCapturedCommandError
	if !errors.As(toolErr, &toolFailure) {
		t.Fatalf("missing actual tool failure: %v", toolErr)
	}
	exit, observed := toolFailure.cause.(*exec.ExitError)
	if !observed || exit.ExitCode() != 2 {
		t.Fatalf("stock Go did not establish the actual exit-two control: %v", toolErr)
	}
	copy := *failures[0]
	copy.cause = toolFailure.cause
	for _, failure := range []error{toolErr, &copy, errors.Join(original, context.Canceled)} {
		_, got := classifyDiscoveryAsmDeclFailure(root, files, files, failure)
		if got == nil || !errors.Is(got, failure) || strings.Contains(got.Error(), "unproved_result_initialization") {
			t.Fatalf("tool/cancel failure acquired a result-only reason: %v", got)
		}
	}

	for name, extra := range map[string]string{
		"another result alias": ":2:1: [amd64] Other: unknown variable ret0; offset 0 is ret+0(FP)\n",
		"parameter alias":      ":2:1: [amd64] Value: unknown variable arg0; offset 0 is x+0(FP)\n",
		"different offset":     ":2:1: [amd64] Value: unknown variable ret0; offset 8 is ret+8(FP)\n",
	} {
		t.Run(name, func(t *testing.T) {
			copy := *failures[0]
			copy.output += filepath.Join(root, files[0]) + extra
			_, got := classifyDiscoveryAsmDeclFailure(root, files, files, &copy)
			if got == nil || strings.Contains(got.Error(), "unproved_result_initialization") {
				t.Fatalf("unrelated alias was hidden by another RET: %v", got)
			}
		})
	}

	writeTestFile(t, filepath.Join(root, files[0]), "TEXT ·Value(SB),4,$0-8\nMOVQ $1,ret+0(FP)\nRET\n")
	changed := plan.run(ctx)
	if changed == nil || !strings.Contains(changed.Error(), "changed") {
		t.Fatalf("actual source mutation did not revoke the observed plan: %v", changed)
	}
	_, got := classifyDiscoveryAsmDeclFailure(root, files, files, changed)
	if got == nil || !errors.Is(got, changed) || strings.Contains(got.Error(), "unproved_result_initialization") {
		t.Fatalf("changed original source gained a stale result reason: %v", got)
	}
}
