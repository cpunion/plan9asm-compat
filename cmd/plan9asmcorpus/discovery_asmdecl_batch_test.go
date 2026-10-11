package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclBatchAttributesEveryActualUnit(t *testing.T) {
	dir, env, files := discoveryAsmDeclBatchFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := runDiscoveryAsmDeclDirect(ctx, dir, env, nil, []string{"./..."}, "")
	if err == nil {
		t.Fatal("two actual invalid MOVQ analyses unexpectedly passed")
	}
	for _, file := range files {
		if !strings.Contains(discoveryCommandDiagnostic(err), file) {
			t.Fatalf("actual diagnostic for %s was lost: %v", file, err)
		}
	}
	rejected, classifyErr := classifyDiscoveryAsmDeclFailure(dir, files, files, err)
	if classifyErr != nil || !reflect.DeepEqual(rejected, files) {
		t.Fatalf("complete independent ABI analyses did not attribute both original files: rejected=%v error=%v", rejected, classifyErr)
	}
	evidence := discoveryAsmDeclRejectionEvidence(dir, err, rejected)
	for _, file := range files {
		if !strings.Contains(evidence, file) {
			t.Fatalf("rejection evidence omitted %s: %s", file, evidence)
		}
	}
}

func TestDiscoveryAsmDeclBatchMixedActualUnitStaysFailed(t *testing.T) {
	dir, env, files := discoveryAsmDeclBatchFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := runDiscoveryAsmDeclDirect(ctx, dir, env, nil, []string{"./..."}, "")
	if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), "RET without writing") {
		t.Fatalf("actual unwritten-result unit did not fail: %v", err)
	}
	if rejected, classifyErr := classifyDiscoveryAsmDeclFailure(dir, files, files, err); classifyErr == nil || len(rejected) != 0 {
		t.Fatalf("one ABI unit swallowed another unit's unwritten result: %v / %v", rejected, classifyErr)
	}
	if discoveryAsmDeclOnlyKnownNonABIWarnings(err) {
		t.Fatal("mixed actual result failure was dismissed as non-ABI warnings")
	}
}

func TestDiscoveryAsmDeclBatchIncompleteAndWrappedReceiptsFail(t *testing.T) {
	dir, env, files := discoveryAsmDeclBatchFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := runDiscoveryAsmDeclDirect(ctx, dir, env, nil, []string{"./..."}, "")
	batch, complete := err.(*discoveryAsmDeclAnalysisError)
	if !complete || len(batch.failures) != 2 {
		t.Fatalf("fixture lacks two actual completed analyzer receipts: %v", err)
	}
	first, second := batch.failures[0], batch.failures[1]
	_, unknown := runCapturedCommandOutput(ctx, dir, env, "go", "env", "-plan9asm-unknown-flag")
	if unknown == nil {
		t.Fatal("actual unknown command unexpectedly succeeded")
	}
	for name, failure := range map[string]error{
		"outer wrapper":        fmt.Errorf("unexplained: %w", err),
		"arbitrary join":       errors.Join(first, second),
		"joined outer failure": errors.Join(err, errors.New("unknown outer failure")),
		"incomplete batch":     combineDiscoveryAsmDeclAnalysisFailures([]error{first}, 1, 2),
		"impossible count":     combineDiscoveryAsmDeclAnalysisFailures([]error{first, second}, 1, 1),
		"duplicate receipt":    combineDiscoveryAsmDeclAnalysisFailures([]error{first, first}, 2, 2),
		"wrapped unit":         combineDiscoveryAsmDeclAnalysisFailures([]error{first, fmt.Errorf("unknown: %w", second)}, 2, 2),
		"unknown exit":         combineDiscoveryAsmDeclAnalysisFailures([]error{first, unknown}, 2, 2),
		"context failure":      combineDiscoveryAsmDeclAnalysisFailures([]error{first, context.Canceled}, 2, 2),
	} {
		t.Run(name, func(t *testing.T) {
			if _, observed := discoveryAsmDeclObservedFailures(failure); observed {
				t.Fatal("uncompleted or unexplained batch acquired completed analysis permission")
			}
			if rejected, classifyErr := classifyDiscoveryAsmDeclFailure(dir, files, files, failure); classifyErr == nil || len(rejected) != 0 {
				t.Fatalf("invalid batch excluded source files: %v / %v", rejected, classifyErr)
			}
		})
	}
	if failure := combineDiscoveryAsmDeclAnalysisFailures(nil, 0, 1); !errors.Is(failure, errDiscoveryAsmDeclSourceProof) {
		t.Fatalf("an unexecuted empty batch passed: %v", failure)
	}
}

func TestDiscoveryAsmDeclBatchMetadataFiltersEveryActualUnit(t *testing.T) {
	dir, env, files := discoveryAsmDeclBatchFixture(t, false)
	for _, file := range files {
		writeTestFile(t, filepath.Join(dir, filepath.FromSlash(file)),
			"TEXT ·Bad(SB),4,$0\nMOVL x+0(FP), AX\nMOVL AX, ret+8(FP)\nRET\n")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := runDiscoveryAsmDeclDirect(ctx, dir, env, nil, []string{"./..."}, "")
	if failures, observed := discoveryAsmDeclObservedFailures(err); !observed || len(failures) != 2 {
		t.Fatalf("fixture did not observe two actual unspecified-argument diagnostics: %v", err)
	}
	if filtered := filterDiscoveryAsmDeclTextMetadata(ctx, dir, env, nil, []string{"./..."}, "", err); filtered != nil {
		t.Fatalf("complete original literal metadata did not filter every unit: %v", filtered)
	}
}

func TestDiscoveryAsmDeclBatchDiagnosticRetainsEveryCompleteOutput(t *testing.T) {
	dir, env, _ := discoveryAsmDeclBatchFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := runDiscoveryAsmDeclDirect(ctx, dir, env, nil, []string{"./..."}, "")
	batch, complete := err.(*discoveryAsmDeclAnalysisError)
	if !complete || len(batch.failures) != 2 {
		t.Fatalf("fixture lacks two actual analyzer receipts: %v", err)
	}
	first, second := *batch.failures[0], *batch.failures[1]
	first.output, first.display = "first complete diagnostic\n"+strings.Repeat("a", 70<<10), "first compact"
	second.output, second.display = "second complete diagnostic\n"+strings.Repeat("b", 70<<10), "second compact"
	joined := fmt.Errorf("outer context: %w", errors.Join(&first, &second))
	diagnostic := discoveryCommandDiagnostic(joined)
	if !strings.Contains(diagnostic, first.output) || !strings.Contains(diagnostic, second.output) || !strings.HasPrefix(diagnostic, "outer context:") {
		t.Fatal("multi-unit full output or surrounding unknown context was truncated")
	}
	if _, observed := discoveryAsmDeclObservedFailures(joined); observed {
		t.Fatal("diagnostic display expansion granted permission to an arbitrary wrapper")
	}
}

func TestDiscoveryAsmDeclBatchPublicEntryNeverReusesFactsSuccess(t *testing.T) {
	dir, env, files := discoveryAsmDeclBatchFixture(t, false)
	observer := filepath.Join(dir, "observer")
	if err := os.Mkdir(observer, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(observer, "observer.go"),
		"package observer\nimport _ \"example.invalid/asmdecl-batch/first\"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := runCapturedCommandOutput(ctx, dir, env, "go", "vet", "-asmdecl", "./observer"); err != nil {
		t.Fatalf("actual dependency facts-only cache warm failed: %v", err)
	}
	for repeat := 0; repeat < 2; repeat++ {
		err := runDiscoveryAsmDecl(ctx, dir, env, "linux/amd64", nil, []string{"./first"})
		if err == nil || !strings.Contains(discoveryCommandDiagnostic(err), "invalid MOVQ") {
			t.Fatalf("public entry %d accepted cached facts-only success: %v", repeat, err)
		}
		rejected, classifyErr := classifyDiscoveryAsmDeclFailure(dir, files[:1], files, err)
		if classifyErr != nil || !reflect.DeepEqual(rejected, files[:1]) {
			t.Fatalf("public entry %d lost actual original source attribution: %v / %v", repeat, rejected, classifyErr)
		}
	}
}

func discoveryAsmDeclBatchFixture(t *testing.T, unwritten bool) (string, []string, []string) {
	t.Helper()
	dir := discoveryAsmDeclRetryPhysicalTemp(t)
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.invalid/asmdecl-batch\n\ngo 1.20\n")
	var files []string
	for _, name := range []string{"first", "second"} {
		pkgDir := filepath.Join(dir, name)
		if err := os.MkdirAll(pkgDir, 0755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(pkgDir, "decl.go"), "package "+name+"\nfunc Bad(x uint32) uint32\n")
		assembly := "TEXT ·Bad(SB),4,$0-12\nMOVQ x+0(FP), AX\nMOVL AX, ret+8(FP)\nRET\n"
		if unwritten && name == "second" {
			assembly = "TEXT ·Bad(SB),4,$0-12\nMOVL x+0(FP), AX\nRET\n"
		}
		file := name + "/decl_amd64.s"
		writeTestFile(t, filepath.Join(dir, filepath.FromSlash(file)), assembly)
		files = append(files, file)
	}
	return dir, discoveryAsmDeclDirectFixtureEnv(t, dir), files
}
