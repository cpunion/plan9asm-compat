package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclOrdinaryGuardRetainsActualCompletedReceipt(t *testing.T) {
	plan, root, _ := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/decl.go": "package fixture\nfunc Probe(x uint32) uint64\n",
		"pkg/native_amd64.s": "#include \"sub/outer.h\"\n#include \"textflag.h\"\n" +
			"TEXT ·Probe(SB),NOSPLIT,$0-16\nMOVQ x+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n",
	})
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
	candidate := discoveryCandidate{Module: plan.Module, Version: plan.Version, AsmFiles: files}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	actual := runDiscoveryAsmDeclDirect(ctx, root, discoveryAsmDeclLocalFixtureEnvironment(t), nil, []string{"./pkg"}, "")
	if _, observed := discoveryAsmDeclObservedFailures(actual); !observed ||
		!strings.Contains(discoveryCommandDiagnostic(actual), "invalid MOVQ") {
		t.Fatalf("official completed analysis did not reproduce the actual ABI error: %v", actual)
	}
	guarded := runDiscoveryOrdinaryGuarded(plan, root, runtime.GOROOT(), candidate, func() error {
		return actual
	})
	if guarded != actual {
		t.Fatalf("successful original-byte guard replaced the completed Wait receipt: %T -> %T: %v", actual, guarded, guarded)
	}
	rejected, classifyErr := classifyDiscoveryAsmDeclFailure(root, files, files, guarded)
	if classifyErr != nil || !reflect.DeepEqual(rejected, files) {
		t.Fatalf("verified unchanged source lost its actual ABI attribution: %v / %v", rejected, classifyErr)
	}

	t.Run("changed original header remains failure", func(t *testing.T) {
		guarded := runDiscoveryOrdinaryGuarded(plan, root, runtime.GOROOT(), candidate, func() error {
			writeTestFile(t, filepath.Join(root, "pkg/sub/outer.h"), "#define CHANGED_ORIGINAL_HEADER 1\n")
			return actual
		})
		if !errors.Is(guarded, actual) || !isDiscoveryInfrastructureFailure(guarded) ||
			!strings.Contains(discoveryCommandDiagnostic(guarded), "invalid MOVQ") ||
			!strings.Contains(discoveryCommandDiagnostic(guarded), "consumed CPP source changed") {
			t.Fatalf("changed input lost either real analysis or verification failure: %v", guarded)
		}
		if _, observed := discoveryAsmDeclObservedFailures(guarded); observed {
			t.Fatal("failed source guard acquired completed-analysis permission")
		}
		if rejected, classifyErr := classifyDiscoveryAsmDeclFailure(root, files, files, guarded); classifyErr == nil || len(rejected) != 0 {
			t.Fatalf("changed original input became source ABI N/A: %v / %v", rejected, classifyErr)
		}
	})
}
