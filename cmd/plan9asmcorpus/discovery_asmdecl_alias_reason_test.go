package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

// These are completed stock-Go analyzer failures, not invented diagnostics.
// The additional reason must not change their outcome, source-exclusion
// category, original command receipt or the authority of the byte proof.
func TestDiscoveryAsmDeclFPAliasRetainsUnderlyingProofReason(t *testing.T) {
	for _, fixture := range []struct {
		name, declaration, prefix, body, header, stage, reason string
	}{
		{
			name: "unknown GP", declaration: "func Value(x, y uint64) uint64",
			body:  "ADDQ x+8(FP),AX\nMOVQ AX,y+16(FP)",
			stage: "result-bytes", reason: "result initialization:",
		},
		{
			name: "partial result read", declaration: "func Value(x, y uint64) uint64",
			body:  "MOVL $1,ret+16(FP)\nMOVQ y+16(FP),AX",
			stage: "result-bytes", reason: "result initialization:",
		},
		{
			name: "opaque pointer load", declaration: "func Value(p *uint64, y uint64) uint64",
			body:  "MOVQ p+0(FP),AX\nMOVQ (AX),BX\nMOVQ BX,y+16(FP)",
			stage: "result-bytes", reason: "result initialization:",
		},
		{
			name: "dynamic FP displacement", declaration: "func Value(x, y uint64) uint64",
			body:  "MOVQ x+8(FP)(SI*1),AX\nMOVQ AX,ret+16(FP)",
			stage: "native-access", reason: "native FP access width/direction is not closed",
		},
		{
			name: "component width", declaration: "func Value(x uint32, y uint32, z uint64) uint64",
			body:  "MOVQ alias+4(FP),AX\nMOVQ AX,ret+16(FP)",
			stage: "native-access", reason: "native FP span does not match an occupied declaration component",
		},
		{
			name: "register macro", declaration: "func Value(x, y uint64) uint64",
			prefix: "#define AX BX\n", body: "MOVQ x+8(FP),AX\nMOVQ AX,ret+16(FP)",
			stage: "native-access", reason: "CPP FP operand 1 is not an exact register alias",
		},
		{
			name: "included register macro", declaration: "func Value(x, y uint64) uint64",
			prefix: "#include \"register.h\"\n", header: "#define AX BX\n",
			body:  "MOVQ x+8(FP),AX\nMOVQ AX,ret+16(FP)",
			stage: "native-access", reason: "CPP FP operand 1 is not an exact register alias",
		},
		{
			name: "generated include", declaration: "const ValueBits = 7\nfunc Value(x, y uint64) uint64",
			prefix: "#include \"go_asm.h\"\n", body: "MOVQ x+8(FP),AX\nMOVQ AX,ret+16(FP)",
			stage: "cpp-replay", reason: "unclosed result-proof include context",
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			assembly := fixture.prefix + "TEXT ·Value(SB),4,$0-24\n" + fixture.body + "\nRET\n"
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, assembly)
			if fixture.header != "" {
				writeTestFile(t, filepath.Join(root, "register.h"), fixture.header)
			}
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
			if len(plan.Units) != 1 {
				t.Fatalf("actual unit denominator: got %d, want 1", len(plan.Units))
			}
			unit := plan.Units[0]
			_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary,
				"tool", "vet", "-asmdecl", unit.Filename)
			failure, observed := discoveryAsmDeclObservedFailure(original)
			if !observed {
				t.Fatalf("missing completed original Exit1: %v", original)
			}
			before := *failure
			filtered := plan.filterResultAliasWarnings(unit, original)
			if !errors.Is(filtered, original) || !errors.Is(filtered, errDiscoveryAsmDeclSourceProof) ||
				!errors.Is(filtered, plan9asm.ErrProbeNeedsContext) || !isDiscoveryInfrastructureFailure(filtered) ||
				!reflect.DeepEqual(before, *failure) || len(plan.resultAliasRawFailures) != 0 {
				t.Fatalf("diagnostic changed the existing failure/category/raw receipt: %v", filtered)
			}
			if rejected, _ := classifyDiscoveryAsmDeclFailure(root, unit.Config.NonGoFiles, unit.Config.NonGoFiles, filtered); len(rejected) != 0 {
				t.Fatalf("unclosed alias became source N/A: %v", rejected)
			}
			diagnostic := discoveryCommandDiagnostic(filtered)
			t.Logf("ORIGINAL_BOUND_RECEIPT: %v\nFAILURE_ONLY_PROOF: %s", original, diagnostic)
			for _, required := range []string{
				failure.output, "stage=" + fixture.stage, "file=decl_amd64.s:",
				"arch=amd64 symbol=Value", fixture.reason,
			} {
				if !strings.Contains(diagnostic, required) {
					t.Errorf("missing actual underlying proof reason %q: %s", required, diagnostic)
				}
			}
			for _, line := range strings.Split(filtered.Error(), "\n") {
				if !strings.HasPrefix(line, "FP alias proof stage=") {
					continue
				}
				bound := false
				for _, raw := range strings.Split(failure.output, "\n") {
					position := discoveryAsmDeclWarningPosition.FindStringSubmatch(strings.TrimSpace(raw))
					if position != nil && strings.Contains(line, "file=decl_amd64.s:"+position[2]+" arch="+position[4]+" symbol="+position[5]+":") {
						bound = true
					}
				}
				if !bound {
					t.Fatalf("proof reason invented a warning source position: %s", line)
				}
			}

			// Cancellation, infrastructure and foreign/unbound command receipts
			// do not gain a fabricated proof stage or source location.
			for _, cause := range []error{context.Canceled, context.DeadlineExceeded, fmt.Errorf("owned infrastructure failure")} {
				copy := before
				copy.cause = cause
				if got := plan.filterResultAliasWarnings(unit, &copy); got != &copy || !errors.Is(got, cause) {
					t.Fatalf("non-observed failure identity changed: %v", got)
				}
			}
			copy := before
			copy.command += " -unbound"
			if got := plan.filterResultAliasWarnings(unit, &copy); got != &copy {
				t.Fatalf("unbound receipt acquired a source/proof stage: %v", got)
			}
		})
	}
}

func TestDiscoveryAsmDeclFPAliasProofReasonKeepsPlainRETIdentity(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value() uint64", "TEXT ·Value(SB),4,$0-8\nRET\n")
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
	if len(plan.Units) != 1 {
		t.Fatalf("actual unit denominator: got %d, want 1", len(plan.Units))
	}
	unit := plan.Units[0]
	_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
	failure, observed := discoveryAsmDeclObservedFailure(original)
	if !observed || !discoveryAsmDeclHasCompletedABIObligation(original) {
		t.Fatalf("missing actual original RET obligation: %v", original)
	}
	before := *failure
	if got := plan.filterResultAliasWarnings(unit, original); got != original ||
		!reflect.DeepEqual(before, *failure) || !discoveryAsmDeclHasCompletedABIObligation(got) {
		t.Fatalf("plain RET-only failure/category changed: %v", got)
	}
}

func TestDiscoveryAsmDeclFPAliasProofReasonKeepsClosedOutcomes(t *testing.T) {
	for _, fixture := range []struct{ name, declaration, assembly, header string }{
		{"numeric parameter alias", "func Value(x, y uint64) uint64", "TEXT ·Value(SB),4,$0-24\nMOVQ x+8(FP),AX\nMOVQ AX,ret+16(FP)\nRET\n", ""},
		{"numeric result alias", "func Value(x, y uint64) uint64", "TEXT ·Value(SB),4,$0-24\nMOVQ $1,AX\nADDQ x+8(FP),AX\nMOVQ AX,y+16(FP)\nRET\n", ""},
		{"whole CPP result", "func Value() uint64", "#include \"store.h\"\nTEXT ·Value(SB),4,$0-8\nSTORE\nRET\n", "#define STORE MOVQ $7,ret0+0(FP)\n"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, fixture.assembly)
			if fixture.header != "" {
				writeTestFile(t, filepath.Join(root, "store.h"), fixture.header)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err != nil {
				t.Fatalf("existing fully closed numeric/CPP outcome changed: %v", err)
			}
		})
	}
}
