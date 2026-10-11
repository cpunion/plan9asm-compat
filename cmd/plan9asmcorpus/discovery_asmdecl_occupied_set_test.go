package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclResultAliasOccupiedAndConditionalBytes(t *testing.T) {
	for _, condition := range strings.Fields("CC CS EQ GE GT HI LE LS LT MI NE OC OS PC PL PS") {
		t.Run(condition, func(t *testing.T) {
			assembly := fmt.Sprintf("TEXT ·Value(SB),4,$0-25\nMOVQ x+8(FP),AX\nCMPQ AX,$0\nSET%s ret0+24(FP)\nRET\n", condition)
			root, env := discoveryAsmDeclResultAliasFixture(t, "func Value(x []uint32) uint8", assembly)
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
				t.Fatal("missing actual selected declaration unit")
			}
			_, original := runCapturedCommandOutput(ctx, root, env, plan.GoBinary, "tool", "vet", "-asmdecl", plan.Units[0].Filename)
			if original == nil || !strings.Contains(discoveryCommandDiagnostic(original), "RET without writing") {
				t.Fatalf("actual stock analyzer did not expose this result-name alias: %v", original)
			}
			t.Logf("PRESERVED_ORIGINAL_RESULT_ALIAS: %v", original)
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err != nil {
				t.Fatalf("whole observed declaration/CPP/result obligation did not close: %v", err)
			}
		})
	}
	for name, body := range map[string]string{
		"unknown flags":    "SETNE ret0+24(FP)\nRET",
		"pointer bits":     "MOVQ x+0(FP),AX\nCMPQ AX,$0\nSETNE ret0+24(FP)\nRET",
		"unwritten branch": "MOVQ x+8(FP),AX\nCMPQ AX,$0\nJE end\nSETNE ret0+24(FP)\nend:\nRET",
		"mixed offset":     "MOVQ x+8(FP),AX\nCMPQ AX,$0\nSETNE ret0+24(FP)\nMOVB AX,alien+999(FP)\nRET",
	} {
		t.Run(name, func(t *testing.T) {
			root, env := discoveryAsmDeclResultAliasFixture(t, "func Value(x []uint32) uint8", "TEXT ·Value(SB),4,$0-25\n"+body+"\n")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err == nil || !discoveryAsmDeclHasUnprovedResultWarning(err) {
				t.Fatalf("missing byte/flag/context or mixed diagnostic was washed into an alias pass: %v", err)
			}
		})
	}
}
