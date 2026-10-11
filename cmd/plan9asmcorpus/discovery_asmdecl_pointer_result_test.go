package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclResultAliasNativePointerReadsRemainUnproved(t *testing.T) {
	for _, fixture := range []struct {
		name, declaration, body string
	}{
		{"integer", "func Value(x *uint32) uint32", "MOVL $0,ret0+8(FP)\nMOVQ x+0(FP),AX\nMOVL (AX),BX\nMOVL BX,ret0+8(FP)"},
		{"floating", "func Value(x *float32) float32", "MOVL $0,ret0+8(FP)\nMOVQ x+0(FP),AX\nMOVSS (AX),X0\nMOVSS X0,ret0+8(FP)"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			assembly := "TEXT ·Value(SB),4,$0-12\n" + fixture.body + "\nRET\n"
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, assembly)
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
				t.Fatalf("expected one actual compilation unit, got %d", len(plan.Units))
			}
			unit := plan.Units[0]
			_, original := runCapturedCommandOutput(ctx, root, env, plan.GoBinary,
				"tool", "vet", "-asmdecl", unit.Filename)
			if _, observed := discoveryAsmDeclObservedFailure(original); !observed ||
				!strings.Contains(discoveryCommandDiagnostic(original), "RET without writing") {
				t.Fatalf("stock Go did not produce the precise alias obligation: %v", original)
			}
			t.Logf("ORIGINAL_NATIVE_POINTER_ALIAS_RECEIPT: %v", original)
			if err := plan.filterResultAliasWarnings(unit, original); err == nil {
				t.Fatal("pointer type alone waived an unproved native-read obligation")
			}
		})
	}
}
